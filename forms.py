from django import forms
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.debug import sensitive_variables
#trunglq add
import onetimepass
from .exceptions import KeystoneAuthException
import argparse
import json
from sqlalchemy import create_engine
import os
import sys

sys.path.append(os.getcwd())
from oslo.config import iniparser

class PropertyCollecter(iniparser.BaseParser):
    def __init__(self):
        super(PropertyCollecter, self).__init__()
        self.key_value_pairs = {}

    def assignment(self, key, value):
        self.key_value_pairs[key] = value

    def new_section(self, section):
        pass

    @classmethod
    def collect_properties(cls, lineiter, sample_format=False):
        def clean_sample(f):
            for line in f:
                if line.startswith("# ") and line != '# nova.conf sample #\n':
                    line = line[2:]
                yield line
        pc = cls()
        if sample_format:
            lineiter = clean_sample(lineiter)
        pc.parse(lineiter)
        return pc.key_value_pairs

# end


class Login(AuthenticationForm):
    """ Form used for logging in a user.

    Handles authentication with Keystone, choosing a tenant, and fetching
    a scoped token token for that tenant.

    Inherits from the base ``django.contrib.auth.forms.AuthenticationForm``
    class for added security features.
    """
    region = forms.ChoiceField(label=_("Region"), required=False)
    username = forms.CharField(label=_("User Name"))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput(render_value=False))
    otp = forms.CharField(label=_("OTP"))
    tenant = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(Login, self).__init__(*args, **kwargs)
        self.fields['region'].choices = self.get_region_choices()
        if len(self.fields['region'].choices) == 1:
            self.fields['region'].initial = self.fields['region'].choices[0][0]
            self.fields['region'].widget = forms.widgets.HiddenInput()

    @staticmethod
    def get_region_choices():
        default_region = (settings.OPENSTACK_KEYSTONE_URL, "Default Region")
        return getattr(settings, 'AVAILABLE_REGIONS', [default_region])


    @sensitive_variables()
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        otp = self.cleaned_data.get('otp')
        region = self.cleaned_data.get('region')
        tenant = self.cleaned_data.get('tenant')

        if not tenant:
            tenant = None

        if not (username and password):
            # Don't authenticate, just let the other validators handle it.
            return self.cleaned_data
#trunglq add
        parser = argparse.ArgumentParser()
        parser.add_argument('-c',default='/etc/keystone/keystone.conf')
        options = parser.parse_args()
        conf_file_options = PropertyCollecter.collect_properties(open(options.c))
        cflag=0
        for k, v in sorted(conf_file_options.items()):
            if k=='connection':
               cflag=1
               break
        if cflag==0:
           print "No connection string"
           return self.cleaned_data

        engine = create_engine(v[0])
        connstring="select extra from user where name= '%s'" %(username)
        connection = engine.connect()
        result = connection.execute(connstring)
        rflag=0
        for row in result:
            sk = json.loads(row['extra'])
            rflag=1
        connection.close()
        if rflag==0:
           return self.cleaned_data
        else:
           try:
             my_secret=sk['secretkey']
             if my_secret=='':
                self.user_cache = authenticate(request=self.request, username=username, password=password, tenant=tenant, auth_url=region)
             else:
                if onetimepass.valid_totp(token=otp, secret=my_secret):
                   try:
                     self.user_cache = authenticate(request=self.request,
                                                    username=username,
                                                    password=password,
                                                    tenant=tenant,
                                                    auth_url=region)
                   except KeystoneAuthException as exc:
                     self.request.session.flush()
                     raise forms.ValidationError(exc)
           except Exception as err:
             self.user_cache = authenticate(request=self.request, username=username, password=password, tenant=tenant, auth_url=region)
        self.check_for_test_cookie()
        return self.cleaned_data
# end
 
