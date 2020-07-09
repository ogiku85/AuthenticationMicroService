using System;
using System.Collections.Generic;
using System.Text;
using AuthenticationMicroService.Models;
using AuthenticationMicroService.Service.DTOs;
using AutoMapper;

namespace AuthenticationMicroService.Service
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, ApplicationUserDTO>();
            CreateMap<ApplicationUserDTO, ApplicationUser>()
                .ForMember(v => v.AccessFailedCount, opt => opt.Ignore())
                .ForMember(v => v.ConcurrencyStamp, opt => opt.Ignore())
                .ForMember(v => v.EmailConfirmed, opt => opt.Ignore())
                .ForMember(v => v.LockoutEnabled, opt => opt.Ignore())
                .ForMember(v => v.LockoutEnd, opt => opt.Ignore())
                .ForMember(v => v.NormalizedEmail, opt => opt.Ignore())
                .ForMember(v => v.NormalizedUserName, opt => opt.Ignore())
                .ForMember(v => v.PasswordHash, opt => opt.Ignore())
                .ForMember(v => v.PhoneNumber, opt => opt.Ignore())
                .ForMember(v => v.PhoneNumberConfirmed, opt => opt.Ignore())
                .ForMember(v => v.SecurityStamp, opt => opt.Ignore())
                .ForMember(v => v.TwoFactorEnabled, opt => opt.Ignore())
                ;

            CreateMap<ApplicationUser, CreateUserDTO>()
                .ForMember(v => v.Password, opt =>opt.Ignore());
            CreateMap<CreateUserDTO, ApplicationUser>()
                .ForMember(v => v.AccessFailedCount, opt => opt.Ignore())
                .ForMember(v => v.ConcurrencyStamp, opt => opt.Ignore())
                .ForMember(v => v.EmailConfirmed, opt => opt.Ignore())
                .ForMember(v => v.LockoutEnabled, opt => opt.Ignore())
                .ForMember(v => v.LockoutEnd, opt => opt.Ignore())
                .ForMember(v => v.NormalizedEmail, opt => opt.Ignore())
                .ForMember(v => v.NormalizedUserName, opt => opt.Ignore())
                .ForMember(v => v.PasswordHash, opt => opt.Ignore())
                .ForMember(v => v.PhoneNumber, opt => opt.Ignore())
                .ForMember(v => v.PhoneNumberConfirmed, opt => opt.Ignore())
                .ForMember(v => v.SecurityStamp, opt => opt.Ignore())
                .ForMember(v => v.TwoFactorEnabled, opt => opt.Ignore())
                ;

        }
    }
}
