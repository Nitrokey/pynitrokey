class NordicSemiException(Exception):
    """
    Exception used as based exception for other exceptions defined in this package.
    """

    def __init__(self, msg, error_code=None):
        super(NordicSemiException, self).__init__(msg)
        self.msg = msg
        self.error_code = error_code
