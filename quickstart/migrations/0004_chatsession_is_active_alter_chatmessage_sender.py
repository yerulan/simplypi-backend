# Generated by Django 5.0.6 on 2024-10-25 13:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("quickstart", "0003_chatsession_title"),
    ]

    operations = [
        migrations.AddField(
            model_name="chatsession",
            name="is_active",
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name="chatmessage",
            name="sender",
            field=models.CharField(
                choices=[("user", "User"), ("gpt", "GPT")], max_length=10
            ),
        ),
    ]
