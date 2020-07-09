using System;
using System.Collections.Generic;
using System.Text;

namespace AuthenticationMicroService.Service.DTOs
{
    public class ApplicationUserDTO
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get; set; }
        public string JobTitle { get; set; }
        public string Department { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}
