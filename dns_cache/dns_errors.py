class DNSError(Exception):
    '''базовый класс для всех днс ошибок'''
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class RcodeError(DNSError):
    '''ошибка из-за rcode != 0'''
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class FormatError(DNSError):
    '''ошибка в формате пакета'''
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class InnerError(DNSError):
    '''внутренняя ошибка в работе сервера'''
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class NotImplemented(DNSError):
    '''ошибка связаная с тем, что функционал не был реализован'''
    def __init__(self, *args: object) -> None:
        super().__init__(*args)