from typing import List, overload


@overload
def se(data_list: List):
    '''
    equal to se(flat(data_list))
    '''
    ...


@overload
def se(data: bytes):
    '''
    GameBox::control send data (NOT contains \n)
    data: what content to send , can be `str` or `bytes`
    '''
    ...


@overload
def sa(data_list: List):
    '''
    equal to sa(flat(data_list))
    '''
    ...


@overload
def sa(data: bytes):
    '''
    GameBox::control send data AFTER `delim` received (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def sl(data_list: List):
    '''
    equal to sl(flat(data_list))
    '''
    ...


@overload
def sl(data: bytes):
    '''
    GameBox::control send data (contains \n)
    data: what content to send , can be `str` or `bytes`
    '''
    ...


@overload
def sla(delim: List, data: List, timeout: int = None):
    '''
    equal to sla(flat(delim_list),flat(data))
    '''
    ...


@overload
def sla(delim: bytes, data: List, timeout: int = None):
    '''
    equal to sla(delim_list,flat(data))
    '''
    ...


@overload
def sla(delim: List, data: bytes, timeout: int = None):
    '''
    equal to sla(flat(delim_list),data)
    '''
    ...


@overload
def sla(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send a line with data after `delim` received (contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def sea(delim: List, data: List, timeout: int = None):
    '''
    equal to sea(flat(delim_list),flat(data))
    '''
    ...


@overload
def sea(delim: bytes, data: List, timeout: int = None):
    '''
    equal to sea(delim_list,flat(data))
    '''
    ...


@overload
def sea(delim: List, data: bytes, timeout: int = None):
    '''
    equal to sea(flat(delim_list),data)
    '''
    ...


@overload
def sea(delim: bytes, data: bytes, timeout: int = None):
    '''
    GameBox::control send data after `delim` received  (NOT contains \n)
    delims: can use str or bytes , for what to watting for
    data: what content to send , can be `str` or `bytes`
    timeout: default is tube.default
    '''
    ...


@overload
def ru(delims_list: List, drop: bool = False, timeout: int = None):
    '''
    equal to ru(flat(delim_list),drop,timeout)
    '''
    ...


@overload
def ru(delims: bytes, drop: bool = False, timeout: int = None):
    '''
    GameBox::control receive data until `delims` comes
    delims: can use str or bytes , for what to watting for
    drop: if set True , the ending content will be drop
    timeout: default is tube.default
    '''
    ...
