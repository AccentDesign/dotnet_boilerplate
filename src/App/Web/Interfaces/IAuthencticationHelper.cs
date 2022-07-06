using IdentityModel.Client;

namespace Web.Interfaces;

public interface IAuthencticationHelper
{
    Task<TokenResponse> GetTokenAsync(PasswordTokenRequest request);
    Task<bool> SignOutAsync();
}