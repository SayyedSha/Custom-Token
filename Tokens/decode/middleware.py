from typing import Any


rtoken=None
def settoken(a):
    global rtoken
    rtoken=a
    return print(rtoken)

class Tokenmiddelware:
    def __init__(self, get_response):
        self.get_response= get_response
    
    def __call__(self, request):
        token=rtoken
        request.META['HTTP_AUTHORIZATION'] = f'Bearer {token}'

        response = self.get_response(request)
        return response