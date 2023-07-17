from django.db import connection
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password, check_password
from datetime import datetime, timedelta
from django.conf import settings
from .middleware import *
import jwt
from geoip2.database import Reader
from django.views import View
import re

cursor=connection.cursor()


# class DeviceInfoView(View):
#     def get(self, request):
#         ip_address = request.META.get('REMOTE_ADDR', '')
#         location = self.get_location(ip_address)
#         device_name = request.META.get('HTTP_USER_AGENT', '')
#         context = {
#         'ip': ip_address,
#         'location': location,
#         'device': device_name
#     }

#         return context
    
#     def get_location(self, ip_address):
#         try:
#             with Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
#                 match = reader.city(ip_address)
#                 if match:
#                     return match.country.names.get('en', '')
#         except Exception as e:
#             print(f"Error retrieving location: {str(e)}")
#         return ''




@api_view(['POST'])
def Authenticate(request):
    #getting data from postman
    username= request.data.get('username')
    password= request.data.get('password')
   
    #Fetching data from table based on user_name 
    cursor.callproc('sp_users_get_by_username',[username])
    result = cursor.fetchall()
    cursor.nextset()
    # columns = [col[0] for col in cursor.description]
    
    if len(result) == 0:
        # No user found with the provided username
        return Response({'message': 'nothing'}, status=401)
    
    # Assuming the stored procedure returns the username and password in the result set
    r_user_id = result[0][0]  # Assuming the username is in the first column
    retrieved_username = result[0][1]  # Assuming the password is in the second column
    retrieved_password = result[0][2]
    retrieved_role= result[0][3]
    print(retrieved_username)
    print(retrieved_role)
    
    if username == retrieved_username and password == retrieved_password or check_password(password,retrieved_password):
        cursor.callproc('SP_Custom_Token_Getting_Data',[r_user_id])
        ex_token=cursor.fetchall()
        cursor.nextset()
        if len(ex_token)!=0:
            token=ex_token[0][6]
            settoken(token)
            return Response({'message': 'Welcome '+' '+retrieved_role}, status=200)
        else:
            ip_address = request.META.get('REMOTE_ADDR', '')
            device_name = request.META.get('HTTP_USER_AGENT', '')
            payload = {
                            'user_id':r_user_id,
                            'username': retrieved_username,
                            'roles': retrieved_role,
                            'exp': datetime.utcnow() + timedelta(days=1)  # Token expiration time
                        }

            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            cursor.callproc('sp_custom_token_insert',[r_user_id,retrieved_username,ip_address,device_name,token])
            settoken(token)
            cursor.nextset()
            return Response({'message': 'Welcome '+retrieved_username+' '+retrieved_role}, status=200)
    else:
        cursor.nextset()
        # Username and password do not match
        return Response({'message': 'Invalid credentials'}, status=401)
    
# Fetching data
@api_view(['GET'])
def get_data(request):
    verify_token=request.META.get('HTTP_AUTHORIZATION')
    if verify_token:
        jwt_token = verify_token.split(' ')[1]
        #Decoding JWT    
        decoded=jwt.decode(jwt_token,settings.SECRET_KEY,algorithms=['HS256'])
        user_id=decoded['user_id']
        rol=decoded['roles']
        user=decoded['username']

        print(rol)
        cursor.callproc('SP_Custom_Token_Getting_Data',[user_id])
        ex_token=cursor.fetchall()
        cursor.nextset()
        if len(ex_token)!=0:
            # Authorizing
            if rol =='admin':
                cursor.callproc('sp_users_fetching')
                result=cursor.fetchall()            
                columns = [col[0] for col in cursor.description]
                data = [dict(zip(columns, row)) for row in result]
                cursor.nextset()
                return JsonResponse(data, safe=False)
            
            #Authorizing
            elif rol=='employee':
                name=user
                cursor.callproc('sp_users_get_by_username_dynamic',[name])
                result = cursor.fetchall()                  
                columns = [col[0] for col in cursor.description]
                
                # Select the columns you want to include in the response
                selected_columns = ['first_name','last_name','username', 'email', 'roles']
                
                # Filter the columns to include only the selected ones
                filtered_columns = [col for col in selected_columns if col in columns]
                
                #Changing data into json
                data = []            
                for row in result:
                    row_data = {}
                    
                    for col in filtered_columns:
                        index = columns.index(col)
                        row_data[col] = row[index]
                    
                    data.append(row_data)
                cursor.nextset()
                return JsonResponse(data, safe=False)
            else:
                return Response({'Message':'Unauthorized'},status=401)
        else:
            return Response({'Message':'Session Expired Please Logging'}, status=401)
    else:
        return Response({'Message':'Please Loggin'})
    

#Creating New User
@api_view(['POST'])
def create_user(request):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
    username_pattern = r'^[a-zA-Z0-9_-]{3,16}$'
    verify_token=request.META.get('HTTP_AUTHORIZATION')
    if verify_token:        
        #Decoding JWT    
        jwt_token = verify_token.split(' ')[1]
        decoded=jwt.decode(jwt_token,settings.SECRET_KEY,algorithms=['HS256'])
        user_id1=decoded['user_id']
        rol=decoded['roles']
        user=decoded['username']
        
        cursor.callproc('SP_Custom_Token_Getting_Data',[user_id1])
        ex_token=cursor.fetchall()
        cursor.nextset()
        if len(ex_token)!=0:
            if rol =='admin':
                first_name=request.data.get('first_name')
                last_name=request.data.get('last_name')
                username=request.data.get('username')
                email=request.data.get('email')
                password=request.data.get('password')
                roles=request.data.get('roles')
                

                #Validations & Handling Duplication
                cursor.callproc('sp_users_get_by_email',[email])
                email_dup=cursor.fetchall()
                if len(email_dup)==0:
                    cursor.nextset()
                    cursor.callproc('sp_users_get_by_username',[username])
                    username_dup=cursor.fetchall()
                    if len(username_dup)==0:
                        if re.match(email_pattern,email):
                            if re.match(username_pattern,username):
                                if re.match(password_pattern,password):
                                    hased_password= make_password(password)
                                    cursor.nextset()
                                    cursor.callproc('sp_users_inserting',[first_name,last_name,username,email,hased_password,roles,user_id1])
                                    cursor.nextset()
                                    return Response({'Message':'Created'},status=201)
                                else:
                                    cursor.nextset()
                                    return Response ({'Message':'Password should have at least 8 characters long. Contains at least one letter (uppercase or lowercase). Contains at least one digit'})
                            else:
                                cursor.nextset()
                                return Response({'Message':'Username should greater than 3 character and it can conaion numbers and special character'})
                        else:
                            cursor.nextset()
                            return Response({'message':'Invalid Email!'})
                    else:
                        cursor.nextset()
                        return Response({'Message':'Username already exist!'},status=503)
                else:
                    cursor.nextset()
                    return Response({'Message':'Email alerady exist!' }, status = 503 )
            else:
                cursor.nextset()
                return Response({'Message':'You are unauthorized to perform the action.'},status=400)
        else:
            cursor.nextset()
            return Response({"message":"Session Expired please logging"})
    else:
        cursor.nextset()
        return Response({'Message':'Please Loggin'},status=400)

#Updating User Detail
@api_view(['PUT'])
def update_user(request):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
    username_pattern = r'^[a-zA-Z0-9_-]{3,16}$'
    verify_token = request.META.get('HTTP_AUTHORIZATION')

    if verify_token:
        # Decoding JWT
        jwt_token = verify_token.split(' ')[1]
        decoded = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
        rol = decoded['roles']
        user = decoded['username']
        user_id = decoded['user_id']


        cursor.callproc('SP_Custom_Token_Getting_Data', [user_id])
        ex_token = cursor.fetchall()
        cursor.nextset()

        if len(ex_token) != 0:
            if rol == 'admin':
                first_name = request.data.get('first_name')
                last_name = request.data.get('last_name')
                username = request.data.get('username')
                old_username = request.data.get('old_username')
                email = request.data.get('email')
                password = request.data.get('password')
                roles = request.data.get('Roles')

                if re.match(email_pattern, email):
                    if re.match(username_pattern, username):
                        if re.match(password_pattern, password):
                            hashed_password = make_password(password)
                            cursor.callproc('sp_users_updating',
                                            [first_name, last_name, username, email, hashed_password, roles, old_username,user_id])
                            cursor.execute('select @error_message_out')
                            out_val = cursor.fetchone()[0]
                            print(out_val)
                            cursor.nextset()
                           
                            return Response({'Message': 'Updated'}, status=201)
                        else:
                            cursor.nextset()
                           
                            return Response({'Message': 'Password should have at least 8 characters long. Contains at least one letter (uppercase or lowercase). Contains at least one digit'})
                    else:
                        cursor.nextset()
                        
                        return Response({'Message': 'Username should be greater than 3 characters and can contain numbers and special characters'})
                else:
                    cursor.nextset()
                       # Close the cursor
                    return Response({'message': 'Invalid Email!'})
            elif rol == 'employee':
                username = request.data.get('username')
                cursor.callproc('sp_users_get_by_username_dynamic', [user])
                result = cursor.fetchall()
                user_id = result[0][0]
                cursor.nextset()

                # Verifying
                if user == username:
                    first_name = request.data.get('first_name')
                    last_name = request.data.get('last_name')
                    email = request.data.get('email')
                    password = request.data.get('password')
                    
                    if re.match(email_pattern, email):
                        if re.match(username_pattern, username):
                            if re.match(password_pattern, password):
                                hashed_password = make_password(password)
                                cursor.callproc('sp_users_Update_by_id',
                                                [user_id,first_name, last_name, email, hashed_password,user_id])
                                cursor.execute('select @error_message_out')
                                out_val = cursor.fetchone()[0]
                                cursor.nextset()
                                   # Close the cursor
                                return Response({'Message': 'Updated'}, status=201)
                            else:
                                cursor.nextset()
                                   # Close the cursor
                                return Response({'Message': 'Password should have at least 8 characters long. Contains at least one letter (uppercase or lowercase). Contains at least one digit'})
                        else:
                            cursor.nextset()
                               # Close the cursor
                            return Response({'Message': 'Username should be greater than 3 characters and can contain numbers and special characters'})
                    else:
                        cursor.nextset()
                           # Close the cursor
                        return Response({'message': 'Invalid Email!'})
                else:
                    cursor.nextset()
                       # Close the cursor
                    return Response({'message': 'Username mismatch'})
        else:
            cursor.nextset()
               # Close the cursor
            return Response({'message': 'User not found'})
    else:
        cursor.nextset()
           # Close the cursor
        return Response({'message': 'Unauthorized'}, status=401)


#Deleting User 
@api_view(['DELETE'])
def delete_user(request):
    verify_token=request.META.get('HTTP_AUTHORIZATION')
    if verify_token:
        #Decoding JWT
        jwt_token = verify_token.split(' ')[1]
        decoded=jwt.decode(jwt_token,settings.SECRET_KEY,algorithms=['HS256'])
        user_id=decoded['user_id']
        rol=decoded['roles']
        user=decoded['username']

        cursor.callproc('SP_Custom_Token_Getting_Data',[user_id])
        ex_token=cursor.fetchall()
        cursor.nextset()
        if len(ex_token)!=0:
            if rol =='admin':
                username=request.data.get('username')
                cursor.callproc('sp_users_get_by_username',[username])
                checker=cursor.fetchall()
                cursor.nextset()
                if len(checker)==0:
                    return Response({'Message': 'No such user found'},status=200)   
                else:    
                    cursor.callproc('sp_users_deleteuser',[username])
                    cursor.nextset()
                    return Response({'Message': 'Deleted'},status=200)
            else:
                cursor.nextset()
                return Response({'Message':'You are unauthorized to perform the action.'},status=400)
        else:
            return Response({"Message":"Session Expired Please Loggin "})
    else:
        return Response({'Message':'You are Unautherized to access this page.'}, status = 503 )
    
#Logout and Destorying Session 
# @api_view(['GET'])
# def logout(request):
#     jwt_token = request.META.get('HTTP_AUTHORIZATION')
#     if jwt_token:
#         settoken(None)
#         response = Response({'status': 'Logged out'}, status=200)
#         return response
#     else:
#         response = Response({'message': "Not logged in"}, status=401)