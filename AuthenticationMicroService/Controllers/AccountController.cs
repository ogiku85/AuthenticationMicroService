using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using AuthenticationMicroService.Service.DTOs;
using AuthenticationMicroService.Service.Factories;
using AuthenticationMicroService.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using AuthenticationMicroService.DTOs;
using AuthenticationMicroService.API.Models.AccountViewModels;
using AuthenticationMicroService.Controllers;

namespace AuthenticationMicroService.API.Controllers
{
    // [Authorize]
    // [Route("[controller]/[action]")]
    //  [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]

   // [ApiController]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

       // private readonly UserManager<ApplicationUser> _userManager;

       // private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        //private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private IConfiguration _config;
        private IGenericObjectFactory<ApplicationUser, ApplicationUserDTO> ApplicationUserFactory;
        private IGenericObjectFactory<ApplicationUser, CreateUserDTO> CreateUserFactory;
        private readonly RoleManager<ApplicationRole> _rolesManager;

        public AccountController(
             // UserManager<ApplicationUser> userManager,
             //SignInManager<ApplicationUser> signInManager,

             UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
          //  IEmailSender emailSender,
            IConfiguration config,
            ILogger<AccountController> logger,
            IGenericObjectFactory<ApplicationUser, ApplicationUserDTO> ApplicationUserFactory,
            IGenericObjectFactory<ApplicationUser, CreateUserDTO> CreateUserFactory,
            RoleManager<ApplicationRole> roleManager
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
           // _emailSender = emailSender;
            _logger = logger;
            _config = config;
            this.ApplicationUserFactory = ApplicationUserFactory;
            this.CreateUserFactory = CreateUserFactory;
            _rolesManager = roleManager;
        }

        [TempData]
        public string ErrorMessage { get; set; }
        [HttpGet]
        [Route("CreateRoleByGet")]
        public async Task CreateRoleByGet(string roleName)
        {
            try
            {
                    var role = await _rolesManager.RoleExistsAsync(roleName);
                    if (!role)
                    {
                        var result = await _rolesManager.CreateAsync(new ApplicationRole { Name = roleName });
                        //
                        _logger.LogInformation("Create {0}: {1}", roleName, result.Succeeded);
                    }
                
            }
            catch (Exception Ex)
            {

            }
        }
        [HttpPost]
        [Route("CreateRole")]
        public async Task<IActionResult> CreateRole2([FromBody]UserRoleParameterDTO userRoleParameter)
        {
            try
            {
                var role = await _rolesManager.RoleExistsAsync(userRoleParameter.Role);
                if (!role)
                {
                    var result = await _rolesManager.CreateAsync(new ApplicationRole { Name = userRoleParameter.Role });
                    //
                    _logger.LogInformation("Create {0}: {1}", userRoleParameter.Role, result.Succeeded);

                    if (result.Succeeded)
                    {
                        return Ok(true);
                    }
                }

            }
            catch (Exception Ex)
            {

            }
            return BadRequest("Role was not created");
        }
        [HttpGet]
        [Route("GetAllUsersInRoles")]
        public async Task<List<ApplicationUserDTO>> GetAllUsersInRoles(string Role)
        {
            List<ApplicationUser> AllUsersInRole = new List<ApplicationUser>();
            List<ApplicationUserDTO> AllUsersInRoleDTO = new List<ApplicationUserDTO>();
            try
            {
                AllUsersInRole = await _userManager.GetUsersInRoleAsync(Role) as List<ApplicationUser>;
                AllUsersInRoleDTO = this.ApplicationUserFactory.CreateGenericObjectDTOList(AllUsersInRole).ToList();
            }
            catch (Exception Ex)
            {
            }
            return AllUsersInRoleDTO;
        }

        [HttpGet]
        [Route("GetAllRoles")]
        public IActionResult GetAllRoles()
        {
            List<ApplicationRole> allRoles = new List<ApplicationRole>();
            try
            {
                allRoles = _rolesManager.Roles.ToList();
                if (allRoles != null && allRoles.Count > 0)
                {
                  //  allRoles.Sort();
                    return Ok(allRoles);
                }
                
            }
            catch (Exception Ex)
            {
            }
            return NotFound("No Roles found.");
        }
        
        [HttpGet]
        [Route("FindByNameAsync")]
        public IActionResult FindByNameAsync(string searchString)
        {
            List<ApplicationUser> userList = new List<ApplicationUser>();
            List<ApplicationUserDTO> userListDTO = new List<ApplicationUserDTO>();
            try
            {
                
                userList = _userManager.Users.Where(u => u.FullName.Contains(searchString)).ToList();
                userListDTO = ApplicationUserFactory.CreateGenericObjectDTOList(userList).ToList();
                if (userListDTO != null && userListDTO.Count > 0)
                {
                    return Ok(userListDTO);
                }

            }
            catch (Exception Ex)
            {
            }
            return NotFound("No Users found.");
        }
        [HttpGet]
        [Route("FindUserByNameOrUsernameFromRole")]
        public async Task<IActionResult> FindUserByNameOrUsernameFromRole(string role, string searchString)
        {
            List<ApplicationUser> AllUsersInRole = new List<ApplicationUser>();
            List<ApplicationUserDTO> AllUsersInRoleDTO = new List<ApplicationUserDTO>();
            List<ApplicationUserDTO> AllUsersInRoleFilteredDTO = new List<ApplicationUserDTO>();
            try
            {
                AllUsersInRole = await _userManager.GetUsersInRoleAsync(role) as List<ApplicationUser>;
                AllUsersInRoleDTO = this.ApplicationUserFactory.CreateGenericObjectDTOList(AllUsersInRole).ToList();

              //  AllUsersInRoleFilteredDTO = AllUsersInRoleDTO.Where(a => (a.FullName.Contains(searchString)) || (a.UserName.Contains(searchString))).ToList();
                AllUsersInRoleFilteredDTO = AllUsersInRoleDTO.Where(a => (a.FullName.Contains(searchString)) || (a.UserName.Contains(searchString)) || (a.Email.Contains(searchString))).ToList();

                if (AllUsersInRoleFilteredDTO != null && AllUsersInRoleFilteredDTO.Count > 0)
                {
                    return Ok(AllUsersInRoleFilteredDTO);
                }
            }
            catch (Exception Ex)
            {
            }
            return NotFound("No Users found.");
            //  return AllUsersInRoleDTO;
        }
        [HttpPost]
        [Route("AddUserToRole")]
        public async Task<IActionResult> AddUserToRole([FromBody]UserRoleParameterDTO UserRoleParameterDTO)
        {
            bool added = false;
            try
            {
                //check if role exists
                var RoleExists = await _rolesManager.RoleExistsAsync(UserRoleParameterDTO.Role);
                if (RoleExists)
                {
                    //gets a user based on username
                    //this gets user from xceed
                    var User = await _userManager.FindByNameAsync(UserRoleParameterDTO.Username);
                    if (User != null)
                    {
                        //new dec 21 2018
                        //get user from local db. the user id generated are usually diffenrent from xcced and local db
                        //hence real local db roles are not returned
                        //var user2 = await _userManager.FindByNameAsync(model.Username);
                        var user3 = await _userManager.FindByEmailAsync(User.Email);
                        //var user3 = await _userManager.FindByNameAsync(User.Email);
                        if ((user3 != null && !string.IsNullOrWhiteSpace(user3.Id))
                            && (User != null && !string.IsNullOrWhiteSpace(User.Id)))
                        {
                            User.Id = user3.Id;
                        }
                        //end
                        //check if user already exists in role
                        bool UserIsInRole = await _userManager.IsInRoleAsync(User, UserRoleParameterDTO.Role);
                        if (UserIsInRole == false)
                        {
                            //check if user is in application db
                            //thois hets user from the local application db
                            //commented out dec 21 2018
                            // var User2 = await _userManager.FindByEmailAsync(User.Email);
                            var User2 = user3;
                            //end
                            if (User2 == null)
                            {
                                bool userAdded = false;
                                string searchStringForSearch = "";
                                string searchString = User.UserName;
                                if (searchString.Contains(@"\"))
                                {
                                    searchStringForSearch = searchString.Substring((searchString.LastIndexOf(@"\")) + 1);

                                }
                                else
                                {
                                    searchStringForSearch = searchString;
                                }
                                User.UserName = searchStringForSearch;
                                var result2 = await _userManager.CreateAsync(User);
                                if (result2.Succeeded)
                                {
                                    userAdded = true;
                                }
                            }
                            else
                            {
                                //new mar 27 2019
                                User = user3;
                            }
                            //adds user to role
                            var result = await _userManager.AddToRoleAsync(User, UserRoleParameterDTO.Role);
                            if (result.Succeeded)
                            {
                                added = true;
                                return Ok(added);
                            }
                        }

                    }

                }

            }
            catch (Exception Ex)
            {

            }

            return BadRequest("User cannot be added to the specified role");
        }

        //new dec 21 2018
        [HttpPost]
        [Route("RemoveUserFromRole")]
        public async Task<IActionResult> RemoveUserFromRole([FromBody]UserRoleParameterDTO UserRoleParameterDTO)
        {
            bool removed = false;
            try
            {
                //check if role exists
                var RoleExists = await _rolesManager.RoleExistsAsync(UserRoleParameterDTO.Role);
                if (RoleExists)
                {
                    //new dec 21 2018
                    //check if africa\\ is missing
                    if (!UserRoleParameterDTO.Username.ToLower().Contains("cyber"))
                    {
                        UserRoleParameterDTO.Username = @"CYBER\" + UserRoleParameterDTO.Username;
                    }
                    //end
                    //gets a user based on username
                    //this gets user from xceed
                    var User = await _userManager.FindByNameAsync(UserRoleParameterDTO.Username);
                    if (User != null)
                    {
                        //new dec 21 2018
                        //get user from local db. the user id generated are usually diffenrent from xcced and local db
                        //hence real local db roles are not returned
                        //var user2 = await _userManager.FindByNameAsync(model.Username);
                        var user3 = await _userManager.FindByEmailAsync(User.Email);

                        if ((user3 != null && !string.IsNullOrWhiteSpace(user3.Id))
                            && (User != null && !string.IsNullOrWhiteSpace(User.Id)))
                        {
                            User.Id = user3.Id;
                        }
                        //end
                        //check if user already exists in role
                        bool UserIsInRole = await _userManager.IsInRoleAsync(user3, UserRoleParameterDTO.Role);
                        if (UserIsInRole == true)
                        {
                            //check if user is in application db
                            //thois hets user from the local application db
                            //commented out dec 21 2018
                            // var User2 = await _userManager.FindByEmailAsync(User.Email);
                            var User2 = user3;
                            //end

                            //remove user from role
                            // var result = await _userManager.RemoveFromRoleAsync(User, UserRoleParameterDTO.Role);

                            var result = await _userManager.RemoveFromRoleAsync(user3, UserRoleParameterDTO.Role);

                            if (result.Succeeded)
                            {
                                removed = true;
                                return Ok(removed);
                            }
                        }

                    }

                }

            }
            catch (Exception Ex)
            {

            }

            return BadRequest(removed);
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("CreateUser")]
        public async Task<IActionResult> CreateUser([FromBody]CreateUserDTO model)
        {
            IdentityResult result;
            try
            {
                var user = this.CreateUserFactory.CreateGenericObject(model);
                result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    return Ok(true);
                }
            }
            catch(Exception Ex)
            {

            }
            return BadRequest("Something went wrong reform the request and try again");
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("CreateToken")]
        public async Task<IActionResult> CreateToken([FromBody]LoginViewModel model)
        {
            IActionResult response = Unauthorized();
            //var user = Authenticate(login);

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true

                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, lockoutOnFailure: false);

                //if(result != null)
                if (result.Succeeded)
                {
                   // var user = await _userManager.FindByNameAsync(model.Username);
                    var user = await _userManager.FindByNameAsync(model.Username);

                    //new mar 11 2019
                    //get user from local db. the user id generated are usually diffenrent from AD and local db
                    //hence real local db roles are not returned
                    //var user2 = await _userManager.FindByNameAsync(model.Username);
                    var user3 = await _userManager.FindByEmailAsync(user.Email);

                    if ((user3 != null && !string.IsNullOrWhiteSpace(user3.Id))
                        && (User != null && !string.IsNullOrWhiteSpace(user.Id)))
                    {
                        user.Id = user3.Id;
                    }
                    //end

                    // Get the roles for the user
                    var userRolesIlist = await _userManager.GetRolesAsync(user);
                    var userRoles = userRolesIlist.ToList();
                    var tokenString = BuildToken(model, user, userRoles);
                    response = Ok(new { token = tokenString });
                    _logger.LogInformation("User logged in.");
                    // Resolve the user via their email
                    // return RedirectToLocal(returnUrl);
                }
            }



            return response;
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("CreateToken2")]
        public async Task<IActionResult> CreateToken2([FromBody]LoginViewModel model)
        {
            // THIS METHOD SIMPLY CREATES TOKEN WITHOUT VALIDATION.
            //IT IS USEFUL WHEN YOU CAN'T REACH AD
            IActionResult response = Unauthorized();
            
            if (ModelState.IsValid)
            {
              
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, lockoutOnFailure: false);

                var user = await _userManager.FindByEmailAsync(model.Email);
                
                // Get the roles for the user
                var userRolesIlist = await _userManager.GetRolesAsync(user);
                    var userRoles = userRolesIlist.ToList();
                    var tokenString = BuildToken(model, user, userRoles);
                    response = Ok(new { token = tokenString });
                    _logger.LogInformation("User logged in.");
                 
               // }
            }



            return response;
        }

        private string BuildToken(LoginViewModel model, ApplicationUser User, List<string> userRoles)
        {
            var claims = new List<Claim> {

        //          new Claim(JwtRegisteredClaimNames.Sub, model.Email != null? model.Email: ""),
        //new Claim(JwtRegisteredClaimNames.Email, model.Email != null? model.Email: ""),
        //new Claim(ClaimTypes.Name, model.Username),
        //new Claim(ClaimTypes.NameIdentifier, User.Id != null ? User.Id: model.Username),

         new Claim(JwtRegisteredClaimNames.Sub, User.Email != null? User.Email: ""),
        new Claim(JwtRegisteredClaimNames.Email, User.Email != null? User.Email: ""),
        new Claim(ClaimTypes.Name, User.UserName),
        new Claim(ClaimTypes.NameIdentifier, User.Id != null ? User.Id: model.Username),
        new Claim("FirstName", User.FirstName !=null ? User.FirstName : ""),
        new Claim("LastName", User.LastName != null ? User.LastName : ""),

        new Claim("FullName", User.FullName != null ? User.FullName : ""),
        new Claim("Email", User.Email != null ? User.Email : ""),
        new Claim("Department", User.Department != null ? User.Department : ""),
        new Claim("JobTitle", User.JobTitle != null ? User.JobTitle : ""),
        new Claim("Username", User.UserName != null ? User.UserName : ""),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (userRoles != null)
            {
                if (userRoles.Count > 0)
                {

                    foreach (var role in userRoles)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role));
                        //new
                        claims.Add(new Claim("Role", role));
                        claims.Add(new Claim("rights", role));
                        //end

                    }
                    claims.Add(new Claim("Role Count", userRoles.Count.ToString()));
                    claims.Add(new Claim("Rights Count", userRoles.Count.ToString()));
                }
            }
           
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // var aud = _config["Jwt:Audience"].ToString();
            //var aud2 = _config["Jwt:Audience0"];

            //var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            //  _config["Jwt:Audience"],
            //  claims,
            //  expires: DateTime.Now.AddMinutes(180),
            //  signingCredentials: creds);

           // var auduse =["http://localhost:5001/", "http://localhost:5009/"];

            var auduse2 = new string[] { "http://localhost:5001/", "http://localhost:5009/" }.ToString();

            //var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            //  _config["Jwt:Audience"],
            //  claims,
            //  expires: DateTime.Now.AddMinutes(180),
            //  signingCredentials: creds);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            "http://localhost:5001/,http://localhost:5005/",
             claims,
             expires: DateTime.Now.AddMinutes(180),
             signingCredentials: creds);

            //   var token = new JwtSecurityToken(
            //claims: claims,
            //expires: DateTime.Now.AddMinutes(180),
            //signingCredentials: creds);
            //   var jwtPayload = new JwtPayload(();
            //   jwtPayload.Aud

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return RedirectToLocal(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa), new { returnUrl, model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToAction(nameof(Lockout));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var model = new LoginWith2faViewModel { RememberMe = rememberMe };
            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return View();
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return View();
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    //var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    //await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User created a new account with password.");
                    return RedirectToLocal(returnUrl);
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToAction(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["LoginProvider"] = info.LoginProvider;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(nameof(ExternalLogin), model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                //var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
                //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                //   $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("A code must be supplied for password reset.");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            AddErrors(result);
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }


        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion
    }
}
