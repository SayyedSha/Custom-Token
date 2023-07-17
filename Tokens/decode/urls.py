from django.urls import path
from .views import *
urlpatterns = [
    path('',Authenticate),
    path('get',get_data),
    path('insert',create_user),
    path('update',update_user),
    path('delete',delete_user)
]
