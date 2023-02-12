# errors.py 


class StandardApiErrorMessage(Exception):
    """ standard exception message """    

    def __init__(self, err: str):
        self.err = err 

    def __str__(self) -> str:
        return repr(self.err)