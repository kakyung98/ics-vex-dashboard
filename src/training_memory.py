"""Keep frozen model input/output matrices at the training compute dtype."""


def cast_frozen_io(model, dtype):
    modules = [model.get_input_embeddings(), model.get_output_embeddings()]
    parameters = {}
    for module in modules:
        if module is not None:
            for parameter in module.parameters():
                if parameter.requires_grad:
                    raise ValueError('Cannot lower storage precision of trainable input/output parameters')
                parameters[id(parameter)] = parameter
    before = sum(p.numel()*p.element_size() for p in parameters.values())
    for parameter in parameters.values():
        parameter.data = parameter.data.to(dtype=dtype)
    after = sum(p.numel()*p.element_size() for p in parameters.values())
    return {'frozen_matrices':len(parameters),'storage_dtype':str(dtype),
            'saved_MiB':(before-after)/2**20,'trainable_parameters_modified':False}
