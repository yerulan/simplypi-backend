from facebook_business.api import FacebookAdsApi
from django.conf import settings

access_token = settings.PIXEL_SECRET_KEY

FacebookAdsApi.init(access_token=access_token)
