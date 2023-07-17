# Generated by Django 4.2.2 on 2023-06-27 06:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('decode', '0003_delete_godview'),
    ]

    operations = [
        migrations.CreateModel(
            name='GodView',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('User_name', models.CharField(max_length=255)),
                ('Start', models.DateTimeField(auto_now_add=True)),
                ('ip', models.CharField(max_length=255)),
                ('device_name', models.CharField(max_length=255)),
                ('JWT_Token', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'Custom_token',
                'managed': False,
            },
        ),
    ]