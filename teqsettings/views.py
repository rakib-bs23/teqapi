# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import requests
from django.shortcuts import render
from rest_framework import viewsets
from teqsettings.serializers import ItemsSerializer

from models import ObItem


class ItemsViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = ObItem.objects.all()
    serializer_class = ItemsSerializer


# Create your views here.
def home(request):
    # Make request
    # url = 'https://rakibul.auth0.com/api/v2/'
    # headers = {'User-Agent': 'github.com/vitorfs/seot'}
    # params = {
    #     'order': 'desc',
    #     'sort': 'votes',
    #     'site': 'stackoverflow',
    #     'pagesize': 3,
    #     'tagged': 'python;django',
    # }
    # r = requests.get(url, params=params, headers=headers)
    # print r



    # conn = http.client.HTTPSConnection("")
    payload = "{\"grant_type\":\"client_credentials\",\"client_id\": \"dUkyKj24VlpLhh3DQH9rIwjQlDZlt1J_\",\"client_secret\": \"PsGRf-GAObyxpUIlAlVbQ0KXWkyQES-mcV_n3JNCjCyfgNFOsFEPx4GuoEQuy34o\",\"audience\": \"https://rakibul.auth0.com/api/v2/\"}"
    headers = {'content-type': "application/json"}
    r = requests.get("https://rakibul.auth0.com/oauth/token", params=payload, headers=headers)
    print(r)

    item_list = ObItem.objects.all()
    context = {'item_list': item_list}
    return render(request, 'teqsettings/index.html', context)
