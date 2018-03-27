from django.shortcuts import render
from django.contrib.auth.models import User
from basic_app.models import UserProfileInfo
from basic_app.forms import UserForm,UserProfileInfoForm

from django.core.urlresolvers import reverse;
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect,HttpResponse
from django.contrib.auth import authenticate,login,logout
# Create your views here.

def index(request):
    return render(request,'basic_app/index.html')

    #we dont call our function logout or login becase we imported them here and may casue collision
    #we add the login_required decorator becasue anyone not logged in may see the logout page and click logout
    #which may casue problems in the page
    #so we make the rule that someone has to be logged in to see the logout view :)

#may be you want to say somethign after someone logged in but to see this one must be logged in
#so we add the validators
@login_required
def special(request):
    return HttpResponse("you are logged in,Nice");

@login_required
def user_logout(request):
    logout(request);
        #automatically logs out the user
    return HttpResponseRedirect(reverse('index'))
        #redirecting them in the homepage

def register(request):
    registered = False;
    if(request.method == "POST"):
        user_form = UserForm(data=request.POST);
        profile_form = UserProfileInfoForm(data=request.POST)
            #grabing both form fromt the input

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save();
                #saving the form nad committing it to database and grabing the saved data
            user.set_password(user.password);
                #we are hashing the password with set_password() and setting it
            user.save();
                #and then saving that hashpassword to the database

            profile = profile_form.save(commit=False);
                #we are saving the form and grabing it but not commiting it to the database
            profile.user = user;
                #we are assigning the above user value to the user attribute of profile_form
                #we need to do it becasue there is a onetoone relation between them
            if 'profile_pic' in request.FILES:
                profile.profile_pic = request.FILES['profile_pic']
                    #similar techniqeu is used in uploading other sort of files
                    #request.FILES is a dictionary and we grab uploaded data with having the
                    #variable name as key
            profile.save()
                #finally we commit data to the database

            registered = True
        else:
            print(user_form.errors,profile_form.errors);
    else:
        user_form = UserForm()
        profile_form =  UserProfileInfoForm();

    return render(request,'basic_app/registration.html',
                        {'registered':registered,'profile_form':profile_form,'user_form':user_form})
                        #returning the data to the html


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username');
            #if method is post then user has submitted his username and PasswordInput
            #we use request.POST.get() method get that username
            #we can do it because in the html we wrote:
                # <label for="username">Username:</label>
		        # <input type="text" name="username" placeholder="Username">
            #so as you see we put name = 'username' , this is now helping us to grab this information
        password = request.POST.get('password')
            #same logic as above
        user = authenticate(username=username,password=password);
            #django witll automatically authenticate this for you
        if user:
            #if user has passed the authentication process
            if user.is_active:
                login(request,user);
                    #if the user is active we log him in
                    #by using login() we imported, we pass in the request and user object returned by authentication process
                return HttpResponseRedirect(reverse('index'));
                    #if they log in we will redirect them in the homepage (that is what we are doing here )
            else:
                #in case user is not active we return a response saying that
                return HttpResponse("acc not active");
        else:
            #some one tried to log in with invalid information
            print("someone tried to log in and failed!");
            print("usernaem: {} and password: {}".format(username,password));
            #we print it out
            return HttpResponse("invalid log in details suppolied")
            #and respond that login credintials were wrong
    else:
        return render(request,'basic_app/login.html',{});
        #incase this was not a post request we simple send them the html
