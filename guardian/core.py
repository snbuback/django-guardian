from __future__ import unicode_literals

from itertools import chain

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from guardian.utils import get_identity
from guardian.utils import get_user_obj_perms_model
from guardian.utils import get_group_obj_perms_model
from guardian.compat import get_user_model


class ObjectPermissionChecker(object):
    """
    Generic object permissions checker class being the heart of
    ``django-guardian``.

    .. note::
       Once checked for single object, permissions are stored and we don't hit
       database again if another check is called for this object. This is great
       for templates, views or other request based checks (assuming we don't
       have hundreds of permissions on a single object as we fetch all
       permissions for checked object).

       On the other hand, if we call ``has_perm`` for perm1/object1, then we
       change permission state and call ``has_perm`` again for same
       perm1/object1 on same instance of ObjectPermissionChecker we won't see a
       difference as permissions are already fetched and stored within cache
       dictionary.
    """
    def __init__(self, user_or_group=None):
        """
        :param user_or_group: should be an ``User``, ``AnonymousUser`` or
          ``Group`` instance
        """
        self.user, self.group = get_identity(user_or_group)
        self._obj_perms_cache = {}

    def has_perm(self, perm, obj):
        """
        Checks if user/group has given permission for object.

        :param perm: permission as string, may or may not contain app_label
          prefix (if not prefixed, we grab app_label from ``obj``)
        :param obj: Django model instance for which permission should be checked

        """
        perm = perm.split('.')[-1]
        if self.user and not self.user.is_active:
            return False
        elif self.user and self.user.is_superuser:
            return True

        perm_objs = [obj]
        while perm_objs:
            perm_obj = perm_objs.pop()
            if perm in self.get_perms(perm_obj, filter_by_content_type=False):
                return True

            if hasattr(perm_obj, 'get_parent_object_permission'):
                perm_objs += getattr(perm_obj, 'get_parent_object_permission')()
        return False

    def get_perms(self, obj, filter_by_content_type=True):
        """
        Returns list of ``codename``'s of all permissions for given ``obj``.

        :param obj: Django model instance for which permission should be checked

        """
        key = self.get_local_cache_key(obj)
        if not key in self._obj_perms_cache:
            raw_perms = self.__get_raw_perms(obj)
            self._obj_perms_cache[key] = raw_perms

        perms = self._obj_perms_cache[key]
        if filter_by_content_type:
            ctype = ContentType.objects.get_for_model(obj)
            return [perm.codename for perm in perms if perm.content_type == ctype]
        return [perm.codename for perm in perms]

    def __get_raw_perms(self, obj):
        """
        Get all perms for ``obj`` (and descendents if exists), without filter by content_type.
        """
        User = get_user_model()
        ctype = ContentType.objects.get_for_model(obj)
        group_model = get_group_obj_perms_model(obj)
        group_rel_name = group_model.permission.field.related_query_name()
        if self.user:
            fieldname = '%s__group__%s' % (
                group_rel_name,
                User.groups.field.related_query_name(),
            )
            group_filters = {fieldname: self.user}
        else:
            group_filters = {'%s__group' % group_rel_name: self.group}
        if group_model.objects.is_generic():
            group_filters.update({
                '%s__content_type' % group_rel_name: ctype,
                '%s__object_pk' % group_rel_name: obj.pk,
            })
        else:
            group_filters['%s__content_object' % group_rel_name] = obj

        if self.user and not self.user.is_active:
            return []
        elif self.user and self.user.is_superuser:
            perms = set(Permission.objects.all())
        elif self.user:
            model = get_user_obj_perms_model(obj)
            related_name = model.permission.field.related_query_name()
            user_filters = {'%s__user' % related_name: self.user}
            if model.objects.is_generic():
                user_filters.update({
                    '%s__content_type' % related_name: ctype,
                    '%s__object_pk' % related_name: obj.pk,
                })
            else:
                user_filters['%s__content_object' % related_name] = obj

            perms_qs = Permission.objects
            # Query user and group permissions separately and then combine
            # the results to avoid a slow query
            user_perms_qs = perms_qs.filter(**user_filters)
            user_perms = user_perms_qs
            group_perms_qs = perms_qs.filter(**group_filters)
            group_perms = group_perms_qs
            perms = set(chain(user_perms, group_perms))
        else:
            #for group
            perms = set(Permission.objects.filter(**group_filters))
        return perms

    def get_local_cache_key(self, obj):
        """
        Returns cache key for ``_obj_perms_cache`` dict.
        """
        ctype = ContentType.objects.get_for_model(obj)
        return (ctype.id, obj.pk)
