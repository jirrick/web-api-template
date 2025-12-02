using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MyProject.Domain;
using MyProject.Infrastructure.Features.Authentication.Constants;
using MyProject.Infrastructure.Features.Authentication.Models;
using MyProject.Infrastructure.Features.Authentication.Options;
using MyProject.Infrastructure.Features.Postgres;

namespace MyProject.Infrastructure.Features.Authentication.Services;

public class AuthenticationService(
    UserManager<ApplicationUser> _userManager,
    SignInManager<ApplicationUser> _signInManager,
    ITokenProvider _tokenProvider,
    TimeProvider _timeProvider,
    IHttpContextAccessor _httpContextAccessor,
    IOptions<JwtOptions> authenticationOptions,
    MyProjectDbContext _dbContext)
{
    private readonly JwtOptions _jwtOptions = authenticationOptions.Value;

    public async Task<Result> Login(string username, string password, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByNameAsync(username);

        if (user is null)
        {
            return Result.Failure("Invalid username or password.");
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);
        if (!signInResult.Succeeded)
        {
            return Result.Failure("Invalid username or password.");
        }

        var accessToken = await _tokenProvider.GenerateAccessToken(user, cancellationToken);
        var refreshTokenString = _tokenProvider.GenerateRefreshToken();
        var utcNow = _timeProvider.GetUtcNow();

        var refreshTokenEntity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = refreshTokenString,
            UserId = user.Id,
            CreatedAt = utcNow.UtcDateTime,
            ExpiredAt = utcNow.UtcDateTime.AddDays(_jwtOptions.RefreshToken.ExpiresInDays),
            Used = false,
            Invalidated = false
        };

        _dbContext.RefreshTokens.Add(refreshTokenEntity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        SetCookie(
            cookieName: CookieNames.AccessToken,
            content: accessToken,
            options: CreateCookieOptions(expiresAt: utcNow.AddMinutes(_jwtOptions.ExpiresInMinutes)));

        SetCookie(
            cookieName: CookieNames.RefreshToken,
            content: refreshTokenString,
            options: CreateCookieOptions(expiresAt: utcNow.AddDays(_jwtOptions.RefreshToken.ExpiresInDays)));

        return Result.Success();
    }

    public async Task Logout()
    {
        // Get user ID before clearing cookies
        var userId = TryGetUserIdFromAccessToken();

        DeleteCookie(CookieNames.AccessToken);
        DeleteCookie(CookieNames.RefreshToken);

        if (userId.HasValue)
        {
            await RevokeUserTokens(userId.Value);
        }
    }

    public async Task<Result> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            return Result.Failure("Refresh token is missing.");
        }

        var storedToken = await _dbContext.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken, cancellationToken);

        if (storedToken is null)
        {
            return Result.Failure("Invalid refresh token.");
        }

        if (storedToken.Invalidated)
        {
            return Result.Failure("Invalid refresh token.");
        }

        if (storedToken.Used)
        {
            // Security alert: Token reuse! Revoke all tokens for this user.
            storedToken.Invalidated = true;
            await RevokeUserTokens(storedToken.UserId);
            return Result.Failure("Invalid refresh token.");
        }

        if (storedToken.ExpiredAt < _timeProvider.GetUtcNow().UtcDateTime)
        {
            storedToken.Invalidated = true;
            await _dbContext.SaveChangesAsync(cancellationToken);
            return Result.Failure("Refresh token has expired.");
        }

        // Mark current token as used
        storedToken.Used = true;

        var user = storedToken.User;
        if (user is null)
        {
            return Result.Failure("User not found.");
        }

        var newAccessToken = await _tokenProvider.GenerateAccessToken(user, cancellationToken);
        var newRefreshTokenString = _tokenProvider.GenerateRefreshToken();
        var utcNow = _timeProvider.GetUtcNow();

        var newRefreshTokenEntity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = newRefreshTokenString,
            UserId = user.Id,
            CreatedAt = utcNow.UtcDateTime,
            ExpiredAt = utcNow.UtcDateTime.AddDays(_jwtOptions.RefreshToken.ExpiresInDays),
            Used = false,
            Invalidated = false
        };

        _dbContext.RefreshTokens.Add(newRefreshTokenEntity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        SetCookie(
            cookieName: CookieNames.AccessToken,
            content: newAccessToken,
            options: CreateCookieOptions(expiresAt: utcNow.AddMinutes(_jwtOptions.ExpiresInMinutes)));

        SetCookie(
            cookieName: CookieNames.RefreshToken,
            content: newRefreshTokenString,
            options: CreateCookieOptions(expiresAt: utcNow.AddDays(_jwtOptions.RefreshToken.ExpiresInDays)));

        return Result.Success();
    }

    private Guid? TryGetUserIdFromAccessToken()
    {
        if (_httpContextAccessor.HttpContext?.Request.Cookies.TryGetValue(
                key: CookieNames.AccessToken,
                value: out var accessToken) is not true)
        {
            return null;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(accessToken))
            {
                return null;
            }

            var jwtToken = handler.ReadJwtToken(accessToken);

            var userIdString = jwtToken.Claims.FirstOrDefault(c => c.Type is JwtRegisteredClaimNames.Sub)?.Value;
            return Guid.TryParse(userIdString, out var userId) ? userId : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task RevokeUserTokens(Guid userId)
    {
        var tokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.Invalidated)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Invalidated = true;
        }

        await _dbContext.SaveChangesAsync();

        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user != null)
        {
            await _userManager.UpdateSecurityStampAsync(user);
        }
    }

    /// <summary>
    /// Gets the current authenticated user information
    /// </summary>
    /// <returns>A Result containing the user if authenticated, or failure if not</returns>
    public async Task<Result<ApplicationUser>> GetCurrentUserAsync()
    {
        var userId = TryGetUserIdFromAccessToken();

        if (!userId.HasValue)
        {
            return Result<ApplicationUser>.Failure("User is not authenticated.");
        }

        var user = await _userManager.FindByIdAsync(userId.Value.ToString());

        if (user is null)
        {
            return Result<ApplicationUser>.Failure("User not found.");
        }

        return Result<ApplicationUser>.Success(user);
    }

    /// <summary>
    /// Gets the roles for a specific user
    /// </summary>
    /// <param name="user">The user to get roles for</param>
    /// <returns>A list of role names</returns>
    public async Task<IList<string>> GetUserRolesAsync(ApplicationUser user)
    {
        return await _userManager.GetRolesAsync(user);
    }

    /// <summary>
    /// Sets the authentication cookie in the HTTP response
    /// </summary>
    /// <param name="cookieName">Name of the cookie</param>
    /// <param name="content">Content to be stored in the cookie</param>
    /// <param name="options">Cookie options</param>
    private void SetCookie(string cookieName, string content, CookieOptions options)
        => _httpContextAccessor.HttpContext?.Response.Cookies.Append(key: cookieName, value: content, options: options);

    /// <summary>
    /// Deletes a specific cookie from the HTTP response
    /// </summary>
    /// <param name="cookieName">Name of the cookie to delete</param>
    private void DeleteCookie(string cookieName)
        => _httpContextAccessor.HttpContext?.Response.Cookies.Delete(
            cookieName,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

    private static CookieOptions CreateCookieOptions(DateTimeOffset expiresAt)
        => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiresAt
        };
}
