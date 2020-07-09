using System.Collections.Generic;
using AutoMapper;

namespace AuthenticationMicroService.Service.Factories
{
    public interface IGenericObjectFactory<GenericObject, GenericObjectDTO>
        where GenericObject : class, new()
        where GenericObjectDTO : class, new()
    {
        IMapper mapper { get; }

        GenericObject CreateGenericObject(GenericObjectDTO GenericObjectDTO);
        GenericObjectDTO CreateGenericObjectDTO(GenericObject GenericObject);
        GenericObjectDTO CreateGenericObjectDTOForUpdate(GenericObject GenericObject, GenericObjectDTO GenericObjectDTO);
        IEnumerable<GenericObjectDTO> CreateGenericObjectDTOList(IEnumerable<GenericObject> GenericObjectList);
        IEnumerable<GenericObjectDTO> CreateGenericObjectDTOListForUpdate(IEnumerable<GenericObject> GenericObjectList, IEnumerable<GenericObjectDTO> GenericObjectDTOList);
        GenericObject CreateGenericObjectForUpdate(GenericObjectDTO GenericObjectDTO, GenericObject GenericObject);
        IEnumerable<GenericObject> CreateGenericObjectList(IEnumerable<GenericObjectDTO> GenericObjectDTOList);
        IEnumerable<GenericObject> CreateGenericObjectListForUpdate(IEnumerable<GenericObjectDTO> GenericObjectDTOList, IEnumerable<GenericObject> GenericObjectList);
    }
}