from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

@login_required
def list_users(request):
    return JsonResponse({'users': []})

@login_required
def delete_user(request, user_id):
    return JsonResponse({'deleted': True})
