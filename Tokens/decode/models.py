from django.db import models

class customtable(models.Model):
    id=models.AutoField(primary_key=True)
    first_name=models.CharField(max_length=255)
    last_name=models.CharField(max_length=255)
    username=models.CharField(max_length=255)
    email=models.CharField(max_length=255)
    passwords=models.CharField(max_length=255)
    Roles=models.CharField(max_length=255)
    creatby=models.IntegerField(blank=True)
    created_at=models.DateField(auto_now_add=True)
    updatedby=models.IntegerField(blank=True)
    update_at=models.DateField(auto_now=True)
    
    class Meta:
        managed=False
        db_table='Users'

class GodView(models.Model):
    id = models.AutoField(primary_key=True, blank=True)
    User_id=models.ForeignKey(customtable,on_delete=models.CASCADE,db_column='User_id')
    User_name=models.CharField(max_length=255)
    Start_time=models.DateTimeField(auto_now_add=True)
    ip=models.CharField(max_length=255)
    device_name=models.CharField(max_length=255)
    JWT_Token=models.CharField(max_length=255)
    class Meta:
        managed=False
        db_table="Custom_token"
