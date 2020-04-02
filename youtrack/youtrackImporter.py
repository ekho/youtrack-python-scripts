import itertools

import youtrack
from youtrack import YouTrackException, Issue
from youtrack.importHelper import create_custom_field

__author__ = 'user'

NAME = 'name'
TYPE = 'type'
POLICY = 'bundle_policy'
AUTO_ATTACHED = 'auto_attached'
NUMBER_IN_PROJECT = 'numberInProject'


class YouTrackImporter(object):
    def __init__(self, source, target, import_config):
        self._source = source
        self._target = target
        self._import_config = import_config

    def do_import(self, projects, new_projects_owner_login='root'):
        project_ids = list(projects.keys())
        self._create_auto_attached_fields()
        self._create_custom_fields(project_ids)
        for project_id, project_name in list(projects.items()):
            self._create_project(project_id, project_name, new_projects_owner_login)
            self._attach_fields_to_project(project_id)
            self._add_value_to_fields_in_project(project_id)
            self._import_issues(project_id)
        self._import_tags(project_ids)
        self._import_issue_links(project_ids)

    def _create_auto_attached_fields(self):
        predefined_fields = self._import_config.get_predefined_fields()
        for field in predefined_fields:
            self._create_field(field[NAME], field[TYPE], field.get(POLICY))

    def _create_field(self, field_name, field_type, attach_bundle_policy, auto_attached=True):
        if field_name in youtrack.EXISTING_FIELDS:
            return
        create_custom_field(self._target, field_type, field_name, auto_attached, bundle_policy=attach_bundle_policy)

    def _create_custom_fields(self, project_ids):
        custom_fields = self._get_custom_fields_for_projects(project_ids)
        for yt_field in custom_fields:
            if (yt_field is not None) and (yt_field[TYPE] is not None):
                self._create_field(yt_field[NAME], yt_field[TYPE], yt_field.get(POLICY), yt_field[AUTO_ATTACHED])

    def _get_custom_fields_for_projects(self, project_ids):
        raise NotImplementedError()

    def _create_project(self, project_id, project_name, project_lead_login):
        try:
            self._target.getProject(project_id)
        except YouTrackException:
            self._target.createProjectDetailed(project_id, project_name, '', project_lead_login)

    def _attach_fields_to_project(self, project_id):
        for yt_field in self._get_custom_fields_for_projects([project_id]):
            field_name = yt_field[NAME]
            try:
                self._target.createProjectCustomFieldDetailed(project_id, field_name, 'No ' + field_name)
            except YouTrackException:
                pass
                # print(u'Field [%s] is already attached' % field_name)

    def _import_issues(self, project_id):
        limit = 100
        all_issues = self._get_issues(project_id)
        while True:
            issues = list(itertools.islice(all_issues, None, limit))
            if not len(issues):
                break
            self._target.importIssues(project_id, project_id + ' assignees',
                [self._to_yt_issue(issue, project_id) for issue in issues])
            for issue in issues:
                issue_id = self._get_issue_id(issue)
                issue_attachments = self._get_attachments(issue)
                yt_issue_id = '%s-%s' % (project_id, issue_id)
                self._import_attachments(yt_issue_id, issue_attachments)

    def _import_tags(self, project_ids):
        limit = 100
        existing_tags = set([])
        for project_id in project_ids:
            all_tags = self._get_issue_tags(project_id)
            while True:
                l = list(itertools.islice(all_tags, None, limit))
                if not len(l):
                    break
                issue_tags = list(zip(*l))[1]
                existing_tags |= set([item for tags in issue_tags for item in tags])
        self._do_import_tags(project_ids, existing_tags)

    def _is_prefix_of_any_other_tag(self, tag, other_tags):
        for t in other_tags:
            if t.startswith(tag) and (t != tag):
                return True
        return False


    def _do_import_tags(self, project_ids, collected_tags):
        tags_to_import_now = set([])
        tags_to_import_after = set([])
        for tag in collected_tags:
            if self._is_prefix_of_any_other_tag(tag, collected_tags):
                tags_to_import_after.add(tag)
            else:
                tags_to_import_now.add(tag)
        for project_id in project_ids:
            for (issue_id, tags) in self._get_issue_tags(project_id):
                yt_issue_id = '%s-%s' % (project_id, issue_id)
                for tag in tags:
                    if tag in tags_to_import_now:
                        try:
                            self._target.executeCommand(yt_issue_id, 'tag ' + tag)
                        except YouTrackException:
                            print(('Failed to import tag for issue [%s]' % yt_issue_id))
        if len(tags_to_import_after):
            self._do_import_tags(project_ids, tags_to_import_after)

    def _import_issue_links(self, project_ids):
        limit = 100
        for project_id in project_ids:
            after = 0
            while True:
                links = self._get_issue_links(project_id, after, limit)
                if not len(links):
                    break
                self._target.importLinks(links)
                after += limit

    def process_field(self, key, project_id, result, value):
        # we do not need fields with empty values
        if value is None:
            return
        if isinstance(value, list) and not len(value):
            return
        if (isinstance(value, str) or isinstance(value, str)) and not len(value):
            return

        #get yt field name and field type
        field_name = self._get_field_name(key, project_id)
        if field_name is None or field_name == NUMBER_IN_PROJECT:
            return
        field_type = self._get_field_type(field_name)
        if (field_type is None) and (field_name not in youtrack.EXISTING_FIELDS):
            return
        value = self.get_field_value(field_name, field_type, value)
        if isinstance(value, list):
            for v in value:
                self._add_value_to_field(project_id, field_name, field_type, v)
        else:
            self._add_value_to_field(project_id, field_name, field_type, value)
        if (field_type is not None) and field_type.startswith('user'):
            if isinstance(value, list):
                value = [v.login for v in value]
            else:
                value = value.login
        if not isinstance(value, list):
            value = str(value)
        result[field_name] = value

    def _to_yt_issue(self, issue, project_id):
        result = Issue()
        result.comments = [self._to_yt_comment(comment) for comment in self._get_comments(issue)]
        result.numberInProject = self._get_issue_id(issue)
        for (key, value) in list(issue.items()):
            self.process_field(key, project_id, result, value)
        return result

    def _get_field_name(self, field_name, project_id):
        field_name = self._import_config.get_field_name(field_name)
        if field_name in youtrack.EXISTING_FIELDS:
            return field_name
        try:
            self._target.getProjectCustomField(project_id, field_name)
            return field_name
        except YouTrackException:
            return None

    def _get_field_type(self, field_name):
        if field_name in youtrack.EXISTING_FIELD_TYPES:
            return youtrack.EXISTING_FIELD_TYPES[field_name]
        try:
            return self._target.getCustomField(field_name).type
        except YouTrackException:
            return None

    def _import_user(self, user):
        self._target.importUsers([user])
        for group in user.getGroups():
            try:
                self._target.createGroup(group)
            except YouTrackException:
                pass
            self._target.setUserGroup(user.login, group.name)

    def _add_value_to_field(self, project_id, field_name, field_type, value):
        if (field_type is not None) and field_type.startswith('user'):
            self._import_user(value)
            value = value.login
        if field_name in youtrack.EXISTING_FIELDS:
            return
        custom_field = self._target.getProjectCustomField(project_id, field_name)
        if hasattr(custom_field, 'bundle'):
            bundle = self._target.getBundle(field_type, custom_field.bundle)
            try:
                self._target.addValueToBundle(bundle, value)
            except YouTrackException:
                pass

    def get_field_value(self, field_name, field_type, value):
        if value is None:
            return None
        values_map = self._import_config.get_value_mapping(field_name)
        if isinstance(value, list):
            return [self.get_field_value(field_name, field_type, v) for v in value]
        if field_type.startswith('user'):
            return self._to_yt_user(value)
        if field_type.lower() == "date":
            return self.to_unix_date(value)
        if isinstance(value, str):
            return values_map.get(value, value)
        if isinstance(value, int):
            return values_map.get(value, str(value))

    def to_unix_date(self, date):
        return date

    def _add_value_to_fields_in_project(self, project_id):
        for field in self._get_fields_with_values(project_id):
            field_name = self._get_field_name(field[NAME], project_id)
            pcf = self._target.getProjectCustomField(project_id, field_name)
            if hasattr(pcf, 'bundle'):
                field_type = pcf.type[0:-3]
                bundle = self._target.getBundle(field_type, pcf.bundle)
                yt_values = [v for v in [field['converter'](value, bundle,
                    lambda name, value_name: self._import_config.get_field_value(name, field_type, value_name)) for
                                         value in
                                         field['values']] if len(v)]
                for value in yt_values:
                    self._target.addValueToBundle(bundle, value)

    def _get_issue_id(self, issue):
        return str(issue[self._import_config.get_key_for_field_name(NUMBER_IN_PROJECT)])

    #Following method should be implemented in inheritors:

    def _get_fields_with_values(self, project_id):
        return []

    def _to_yt_comment(self, comment):
        raise NotImplementedError

    def _get_attachments(self, issue_id):
        return []

    def _get_issues(self, project_id):
        raise NotImplementedError

    def _import_attachments(self, issue_id, issue_attachments):
        for attach in issue_attachments:
            self._target.createAttachmentFromAttachment(issue_id, attach)

    def _get_comments(self, issue):
        raise NotImplementedError

    def _get_issue_tags(self, project_id):
        key = self._import_config.get_key_for_field_name('Tags')
        return ((self._get_issue_id(issue), issue[key]) for issue in self._get_issues(project_id) if (key in issue ) and len(issue[key]))

    def _get_issue_links(self, project_id, after, limit):
        return []

    def _to_yt_user(self, value):
        raise NotImplementedError


class YouTrackImportConfig(object):
    def __init__(self, name_mapping, type_mapping, value_mapping=None, link_type_mapping=None):
        self._name_mapping = name_mapping
        self._type_mapping = type_mapping
        self._value_mapping = value_mapping if value_mapping is not None else {}
        self._link_type_mapping = link_type_mapping if link_type_mapping is not None else {}

    def _get_default_auto_attached(self):
        return True

    def _get_default_bundle_policy(self):
        return 0

    def get_field_name(self, field_name):
        return field_name if field_name not in self._name_mapping else self._name_mapping[field_name]

    def get_predefined_fields(self):
        return []

    def get_link_type(self, type):
        return self._link_type_mapping[type] if type in self._link_type_mapping else type

    def get_key_for_field_name(self, field_name):
        for (key, value) in list(self._name_mapping.items()):
            if value == field_name:
                return key
        return field_name

    def get_value_mapping(self, field_name):
        return self._value_mapping[field_name] if field_name in self._value_mapping else {}
