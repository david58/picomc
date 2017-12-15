class Proxy(object):
    def __init__(self, wrapped):
        self.__dict__['__wrapped__'] = wrapped

    @property
    def __class__(self):
        return self.__wrapped__().__class__

    def __getattr__(self, name):
        return getattr(self.__wrapped__(), name)

    def __setattr__(self, name, value):
        return setattr(self.__wrapped__(), name, value)

    def __delattr__(self, name):
        return delattr(self.__wrapped__(), name)
