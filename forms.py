from django import forms
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.debug import sensitive_variables
import onetimepass
from .exceptions import KeystoneAuthException
from smtplib import SMTP

def sendcode(emailfrom, emailto, passwd, msg):
    try :
        conn = SMTP("smtp.gmail.com",587)
        conn.ehlo()
        conn.starttls()
        conn.ehlo
        conn.login(emailfrom,passwd)
        message = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (emailfrom, emailto, "Validation code", msg)
        conn.sendmail(emailfrom,emailto, message)
        conn.close()
    except Exception as err:
        print err


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
        
        my_secret = 'MFRGGZDFMZTWQ2LK'
        my_token = onetimepass.get_totp(my_secret)
#        sendcode('openstacktest@gmail.com','20082778@student.hut.edu.vn','1qa2ws3ed4',otp)
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
        self.check_for_test_cookie()
        return self.cleaned_data
