using AutoMapper;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AuthenticationMicroService.Service.Factories
{
    public class GenericObjectFactory<GenericObject, GenericObjectDTO> : IGenericObjectFactory<GenericObject, GenericObjectDTO> where GenericObject : class, new() where GenericObjectDTO : class, new()
    {
        public IMapper mapper { get; }
        public GenericObjectFactory(IMapper mapper)
        {
            this.mapper = mapper;

        }

        public GenericObject CreateGenericObject(GenericObjectDTO GenericObjectDTO)
        {
            GenericObject GenericObject = new GenericObject();
            try
            {
                Log.Information("Inside CreateGenericObject method");
                Log.Information("GenericObjectDTO is {@GenericObjectDTO}", GenericObjectDTO);
                GenericObject = mapper.Map<GenericObjectDTO, GenericObject>(GenericObjectDTO);
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObject");
            }
            Log.Information("GenericObject is {@GenericObject}", GenericObject);
            return GenericObject;
        }
        public GenericObject CreateGenericObjectForUpdate(GenericObjectDTO GenericObjectDTO, GenericObject GenericObject)
        {
           
            try
            {
                Log.Information("Inside CreateGenericObjectForUpdate method");
                Log.Information("GenericObjectDTO is {@GenericObjectDTO} and GenericObject is {@GenericObject}", GenericObjectDTO, GenericObject);
                GenericObject = mapper.Map<GenericObjectDTO, GenericObject>(GenericObjectDTO);
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObject");

            }
            Log.Information("GenericObject is {@GenericObject}", GenericObject);

            return GenericObject;
        }
        public IEnumerable<GenericObject> CreateGenericObjectList(IEnumerable<GenericObjectDTO> GenericObjectDTOList)
        {
            GenericObject GenericObject = new GenericObject();
            List<GenericObject> GenericObjectList = new List<GenericObject>();
            try
            {
                Log.Information("Inside CreateGenericObjectList method");
                Log.Information("GenericObjectDTOList is {@GenericObjectDTOList}", GenericObjectDTOList);
                GenericObjectList = mapper.Map<IEnumerable<GenericObjectDTO>, IEnumerable<GenericObject>>(GenericObjectDTOList).ToList();
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectList");
            }
            Log.Information("GenericObjectList is {@GenericObjectList}", GenericObjectList);
            return GenericObjectList;
        }
        public IEnumerable<GenericObject> CreateGenericObjectListForUpdate(IEnumerable<GenericObjectDTO> GenericObjectDTOList, IEnumerable<GenericObject> GenericObjectList)
        {
            GenericObject GenericObject = new GenericObject();
           
            try
            {
                Log.Information("Inside CreateGenericObjectListForUpdate method");
                Log.Information("GenericObjectDTOList is {@GenericObjectDTOList} and GenericObjectList is {@GenericObjectList}", GenericObjectDTOList, GenericObjectList);

                GenericObjectList = mapper.Map<IEnumerable<GenericObjectDTO>, IEnumerable<GenericObject>>(GenericObjectDTOList).ToList();
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectListForUpdate");

            }
            Log.Information("GenericObjectList is {@GenericObjectList}", GenericObjectList);

            return GenericObjectList;
        }

        public GenericObjectDTO CreateGenericObjectDTO(GenericObject GenericObject)
        {
            GenericObjectDTO GenericObjectDTO = new GenericObjectDTO();
            try
            {
                Log.Information("Inside CreateGenericObjectDTO method");
                Log.Information("GenericObject is {@GenericObject}", GenericObject);
                GenericObjectDTO = mapper.Map<GenericObject, GenericObjectDTO>(GenericObject);
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectDTO");

            }
            Log.Information("GenericObjectDTO is {@GenericObjectDTO}", GenericObjectDTO);

            return GenericObjectDTO;
        }
        public GenericObjectDTO CreateGenericObjectDTOForUpdate(GenericObject GenericObject, GenericObjectDTO GenericObjectDTO)
        {
           
            try
            {
                Log.Information("Inside CreateGenericObjectDTOForUpdate method");
                Log.Information("GenericObject is {@GenericObject} and GenericObjectDTO is {@GenericObjectDTO}", GenericObject, GenericObjectDTO);

                GenericObjectDTO = mapper.Map<GenericObject, GenericObjectDTO>(GenericObject);
            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectDTOForUpdate");
            }
            Log.Information("GenericObjectDTO is {@GenericObjectDTO}", GenericObjectDTO);
            return GenericObjectDTO;
        }

        public IEnumerable<GenericObjectDTO> CreateGenericObjectDTOList(IEnumerable<GenericObject> GenericObjectList)
        {
            GenericObjectDTO GenericObjectDTO = new GenericObjectDTO();
            List<GenericObjectDTO> GenericObjectDTOList = new List<GenericObjectDTO>();
            try
            {
                Log.Information("Inside CreateGenericObjectDTOList method");
                Log.Information("GenericObjectList is {@GenericObjectList}", GenericObjectList);
                GenericObjectDTOList = mapper.Map<IEnumerable<GenericObject>, IEnumerable<GenericObjectDTO>>(GenericObjectList).ToList();

            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectDTOList");
            }
            Log.Information("GenericObjectDTOList is {@GenericObjectDTOList}", GenericObjectDTOList);
            return GenericObjectDTOList;
        }

        public IEnumerable<GenericObjectDTO> CreateGenericObjectDTOListForUpdate(IEnumerable<GenericObject> GenericObjectList, IEnumerable<GenericObjectDTO> GenericObjectDTOList)
        {
            GenericObjectDTO GenericObjectDTO = new GenericObjectDTO();
             
            try
            {
                Log.Information("Inside CreateGenericObjectDTOListForUpdate method");
                Log.Information("GenericObjectList is {@GenericObjectList} and GenericObjectDTOList is {@GenericObjectDTOList}", GenericObjectList, GenericObjectDTOList);

                GenericObjectDTOList = mapper.Map<IEnumerable<GenericObject>, IEnumerable<GenericObjectDTO>>(GenericObjectList).ToList();

            }
            catch (Exception Ex)
            {
                Log.Error(Ex, "An error has occured in CreateGenericObjectDTOListForUpdate");

            }
            Log.Information("GenericObjectDTOList is {@GenericObjectDTOList}", GenericObjectDTOList);

            return GenericObjectDTOList;
        }


    }
}
