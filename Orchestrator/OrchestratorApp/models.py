from django.db import models


# Create your models here.
class ReconProfile(models.Model):
    name = models.CharField(max_length=30)
    scan_mode = models.CharField(max_length=30)
    project = models.CharField(max_length=30)
    target = models.CharField(max_length=30)
