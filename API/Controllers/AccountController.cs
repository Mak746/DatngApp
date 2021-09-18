
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interface;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
 public class AccountController : BaseApiController
 {
  private readonly DataContext _context;
  private readonly ITokenService _tokenService;
  public AccountController(DataContext context, ITokenService tokenService)
  {
   _tokenService = tokenService;
   _context = context;

  }

  [HttpPost("register")]
  public async Task<ActionResult<UserDto>> Register(RegisterDtos registerDtos)
  {
   using var hmac = new HMACSHA512();
   if (await UserExists(registerDtos.Username)) return BadRequest("Username is Already Taken");
   var user = new AppUser
   {

    UserName = registerDtos.Username.ToLower(),
    PasswordHash = hmac.ComputeHash(buffer: Encoding.UTF8.GetBytes(registerDtos.Password)),
    PasswordSalt = hmac.Key
   };
   _context.Users.Add(user);
   await _context.SaveChangesAsync();
   return new UserDto
   {
    Username = user.UserName,
    Token = _tokenService.CreateToken(user)
   };
  }
  [HttpPost("login")]
  public async Task<ActionResult<UserDto>> Login(LoginDtos loginDtos)
  {
   var user = await _context.Users.SingleOrDefaultAsync(t => t.UserName == loginDtos.Username);




   return new UserDto{
        Username=user.UserName,
        Token=_tokenService.CreateToken(user)
   };
  }
  private async Task<bool> UserExists(string Username)
  {
   return await _context.Users.AnyAsync(t => t.UserName == Username.ToLower());

  }

 }
}