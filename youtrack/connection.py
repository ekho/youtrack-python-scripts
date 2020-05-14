import calendar
import collections
import datetime
import functools
import json
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
from xml.dom import Node
from xml.dom import minidom
from xml.sax.saxutils import escape, quoteattr
import httplib2
import youtrack
import requests


def relogin_on_401(f):
    @functools.wraps(f)
    def wrapped(self, *args, **kwargs):
        attempts = 10
        while attempts:
            try:
                return f(self, *args, **kwargs)
            except youtrack.YouTrackException as e:
                if e.response.status not in (401, 403, 500, 504):
                    raise e
                if e.response.status == 504:
                    time.sleep(30)
                elif self._last_credentials is not None:
                    self._login(*self._last_credentials)
                else:
                    break
                attempts -= 1
        return f(self, *args, **kwargs)

    return wrapped


class Connection(object):
    def __init__(self, url, login=None, password=None, proxy_info=None, token=None):
        if proxy_info is None:
            self.http = httplib2.Http(disable_ssl_certificate_validation=True)
        else:
            self.http = httplib2.Http(disable_ssl_certificate_validation=True,
                                      proxy_info=proxy_info)

        self.url = url.rstrip('/')
        self.baseUrl = self.url + "/rest"
        self.headers = dict()
        self._last_credentials = None

        if token:
            self.set_auth_token(token)
        elif login:
            self._login(login, password)

    def set_auth_token(self, token):
        if token:
            self.headers = {'Authorization': 'Bearer ' + token}

    def _login(self, login, password):
        if login is None:
            login = ''
        if password is None:
            password = ''
        body = 'login=%s&password=%s' % (urllib.parse.quote(login), urllib.parse.quote(password))
        response, content = self.http.request(
            uri=self.baseUrl + '/user/login',
            method='POST',
            body=body,
            headers={'Connection': 'keep-alive',
                     'Content-Type': 'application/x-www-form-urlencoded',
                     'Content-Length': str(len(body))}
        )
        if response.status != 200:
            raise youtrack.YouTrackException('/user/login', response, content)
        self.headers = {'Cookie': response['set-cookie'],
                        'Cache-Control': 'no-cache'}
        self._last_credentials = (login, password)

    @staticmethod
    def __get_illegal_xml_chars_re():
        _illegal_unichrs = [(0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F),
                            (0x7F, 0x84), (0x86, 0x9F), (0xFDD0, 0xFDDF),
                            (0xFFFE, 0xFFFF)]
        _illegal_ranges = ["%s-%s" % (chr(low), chr(high))
                           for (low, high) in _illegal_unichrs]
        return re.compile(b'[%s]' % ''.join(_illegal_ranges))

    @relogin_on_401
    def _req(self, method, url, body=None, ignoreStatus=None, content_type=None):
        headers = self.headers
        if method == 'PUT' or method == 'POST':
            headers = headers.copy()
            if body:
                if isinstance(body, str):
                    body = body.encode('utf-8')

                if content_type is None:
                    content_type = 'application/xml; charset=UTF-8'

                headers['Content-Type'] = content_type
                headers['Content-Length'] = str(len(body))
        elif method == 'GET' and content_type is not None:
            headers = headers.copy()
            headers['Accept'] = content_type

        # print('METHOD: %s; URL: %s; BODY: %s' % (method, url, body))

        if url.startswith('http'):
            response, content = self.http.request(
                url,
                method,
                headers=headers,
                body=body)
        else:
            response, content = self.http.request(
                (self.baseUrl + url),
                method,
                headers=headers,
                body=body)

        # if response.get('content-type', '').lower().find('/xml') != -1:
        #    # Remove invalid xml/utf-8 data
        #    content = re.sub(self.__get_illegal_xml_chars_re(), b'', content)

        # TODO: Why do we need this?
        # content = content.translate(None, '\0')
        content = re.sub(b'system_user[%@][a-zA-Z0-9]+', b'guest', content)

        if response.status not in (200, 201) and \
                (ignoreStatus != response.status):
            raise youtrack.YouTrackException(url, response, content)

        return response, content

    def _reqXml(self, method, url, body=None, ignoreStatus=None):
        if isinstance(body, ElementTree.Element):
            body = ElementTree.tostring(body, encoding='utf-8', method='xml')

        response, content = self._req(
            method, url, body, ignoreStatus, "application/xml")
        if "content-type" in response:
            if response["content-type"].find("/xml") != -1 and content:
                try:
                    return minidom.parseString(content)
                except Exception as e:
                    print((str(e)))
                    return ""
            elif response["content-type"].find("/json") != -1 and content:
                try:
                    return json.loads(content)
                except Exception as e:
                    print((str(e)))
                    return ""

        if method == 'PUT' and ('location' in response):
            return 'Created: ' + response['location']
        else:
            return content

    def _get(self, url):
        return self._reqXml('GET', url)

    def _put(self, url):
        return self._reqXml('PUT', url, '<empty/>\n\n')

    def getIssue(self, id):
        return youtrack.Issue(self._get("/issue/" + id), self)

    def createIssue(self, project, assignee, summary, description, priority=None, type=None, subsystem=None, state=None,
                    affectsVersion=None,
                    fixedVersion=None, fixedInBuild=None, permittedGroup=None):
        params = {'project': project,
                  'summary': summary}
        if description is not None:
            params['description'] = description
        if assignee is not None:
            params['assignee'] = assignee
        if priority is not None:
            params['priority'] = priority
        if type is not None:
            params['type'] = type
        if subsystem is not None:
            params['subsystem'] = subsystem
        if state is not None:
            params['state'] = state
        if affectsVersion is not None:
            params['affectsVersion'] = affectsVersion
        if fixedVersion is not None:
            params['fixVersion'] = fixedVersion
        if fixedInBuild is not None:
            params['fixedInBuild'] = fixedInBuild
        if permittedGroup is not None:
            params['permittedGroup'] = permittedGroup

        return self._req('PUT', '/issue', urllib.parse.urlencode(params),
                         content_type='application/x-www-form-urlencoded')

    def deleteIssue(self, issue_id):
        return self._req('DELETE', '/issue/%s' % issue_id)

    def get_changes_for_issue(self, issue):
        return [youtrack.IssueChange(change, self) for change in
                self._get("/issue/%s/changes" % issue).getElementsByTagName('change')]

    def getComments(self, id):
        response, content = self._req('GET', '/issue/' + id + '/comment')
        xml = minidom.parseString(content)
        return [youtrack.Comment(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getAttachments(self, id):
        response, content = self._req('GET', '/issue/' + id + '/attachment')
        xml = minidom.parseString(content)
        return [youtrack.Attachment(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getAttachmentContent(self, url):
        f = urllib.request.urlopen(urllib.request.Request(self.url + url, headers=self.headers))
        return f

    def deleteAttachment(self, issue_id, attachment_id):
        return self._req('DELETE', '/issue/%s/attachment/%s' % (issue_id, attachment_id))

    def createAttachmentFromAttachment(self, issueId, a):
        try:
            content = a.getContent()
            contentLength = None
            if 'content-length' in content.headers:
                contentLength = int(content.headers['content-length'])
            res = self.importAttachment(issueId, a.name, content, a.authorLogin,
                                         contentLength=contentLength,
                                         contentType=content.info().get_content_type(),
                                         created=a.created if hasattr(a, 'created') else None,
                                         group=a.group if hasattr(a, 'group') else '')

            print("Issue [ %s ] imported attachment: %s from %s" % (issueId, a.name, a.url))
            return res
        except urllib.error.HTTPError as e:
            try:
                reason = e.read().decode('utf-8').replace("\n", ' ')[:100]
                print("Issue [ %s ] import attachment failed: %s from %s; code: %s; reason: %s" % (issueId, a.name, a.url, str(e.code), reason))
            except Exception as e:
                print("Issue [ %s ] import attachment failed: %s" % (issueId, str(e)))
        except Exception as e:
            try:
                print("Issue [ %s ] import attachment failed: code= %s; url= %s; info= %s" % (issueId, str(content.getcode()), str(content.geturl()), str(content.info())))
            except Exception as e:
                print("Issue [ %s ] import attachment failed: %s" % (issueId, str(e)))
            raise e

    def _process_attachments(self, authorLogin, content, contentLength, contentType, created, group, issueId, name,
                             url_prefix='/issue/'):
        if contentType is not None:
            content.contentType = contentType
        if contentLength is not None:
            content.contentLength = contentLength
        elif not isinstance(content, file):
            tmp = tempfile.NamedTemporaryFile(mode='w+b')
            content_content = content.read()
            if isinstance(content_content, str):
                content_content = content_content.encode('utf8')
            tmp.write(content_content)
            tmp.flush()
            tmp.seek(0)
            content = tmp

        post_data = {name: content}
        headers = self.headers.copy()

        # name without extension to workaround: http://youtrack.jetbrains.net/issue/JT-6110
        params = {  # 'name': os.path.splitext(name)[0],
            'authorLogin': authorLogin,
        }
        if group is not None:
            params["group"] = group
        if created is not None:
            params['created'] = created
        else:
            try:
                params['created'] = self.getIssue(issueId).created
            except youtrack.YouTrackException:
                params['created'] = str(calendar.timegm(datetime.now().timetuple()) * 1000)

        url = self.baseUrl + url_prefix + issueId + "/attachment"

        try:
            res = requests.post(url, params=params, headers=headers, files=post_data)
            res.raise_for_status()
        except requests.exceptions.RequestException as e:
            if e.code == 201:
                return e.msg + ' ' + name
            raise e
        return res

    def createAttachment(self, issueId, name, content, authorLogin='', contentType=None, contentLength=None,
                         created=None, group=''):
        return self._process_attachments(authorLogin, content, contentLength, contentType, created, group, issueId,
                                         name)

    def importAttachment(self, issue_id, name, content, authorLogin, contentType, contentLength, created=None,
                         group=''):
        return self._process_attachments(authorLogin, content, contentLength, contentType, created, group, issue_id,
                                         name, '/import/')

    def getLinks(self, id, outwardOnly=False):
        response, content = self._req('GET', '/issue/' + urllib.parse.quote(id) + '/link')
        xml = minidom.parseString(content)
        res = []
        for c in [e for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]:
            link = youtrack.Link(c, self)
            if link.source == id or not outwardOnly:
                res.append(link)
        return res

    def getUser(self, login):
        """ http://confluence.jetbrains.net/display/YTD2/GET+user
        """
        if login.startswith('system_user'):
            login = 'guest'
        return youtrack.User(self._get("/admin/user/" + urllib.parse.quote(login)), self)

    def createUser(self, user):
        """ user from getUser
        """
        # self.createUserDetailed(user.login, user.fullName, user.email, user.jabber)
        self.importUsers([user])

    def createUserDetailed(self, login, fullName, email, jabber):
        self.importUsers([{'login': login, 'fullName': fullName, 'email': email, 'jabber': jabber}])

    #        return self._put('/admin/user/' + login + '?' +
    #                         'password=' + password +
    #                         '&fullName=' + fullName +
    #                         '&email=' + email +
    #                         '&jabber=' + jabber)

    def importUsers(self, users):
        """ Import users, returns import result (http://confluence.jetbrains.net/display/YTD2/Import+Users)
            Example: importUsers([{'login':'vadim', 'fullName':'vadim', 'email':'eee@ss.com', 'jabber':'fff@fff.com'},
                                  {'login':'maxim', 'fullName':'maxim', 'email':'aaa@ss.com', 'jabber':'www@fff.com'}])
        """
        if len(users) <= 0: return

        known_attrs = ('login', 'fullName', 'email', 'jabber')

        xml = '<list>\n'
        for u in users:
            xml += '  <user ' + "".join(k + '=' + quoteattr(u[k]) + ' ' for k in u if k in known_attrs) + '/>\n'
        xml += '</list>'
        # TODO: convert response xml into python objects
        return self._reqXml('PUT', '/import/users', xml, 400).toxml()

    def importIssuesXml(self, projectId, assigneeGroup, xml):
        return self._reqXml('PUT', '/import/' + urllib.parse.quote(projectId) + '/issues?' +
                            urllib.parse.urlencode({'assigneeGroup': assigneeGroup}),
                            xml, 400).toxml()

    def importLinks(self, links):
        """ Import links, returns import result (http://confluence.jetbrains.net/display/YTD2/Import+Links)
            Accepts result of getLinks()
            Example: importLinks([{'login':'vadim', 'fullName':'vadim', 'email':'eee@ss.com', 'jabber':'fff@fff.com'},
                                  {'login':'maxim', 'fullName':'maxim', 'email':'aaa@ss.com', 'jabber':'www@fff.com'}])
        """
        xml = '<list>\n'
        for l in links:
            # ignore typeOutward and typeInward returned by getLinks()
            xml += '  <link ' + "".join(attr + '=' + quoteattr(l[attr]) +
                                        ' ' for attr in l if attr not in ['typeInward', 'typeOutward']) + '/>\n'
        xml += '</list>'
        # TODO: convert response xml into python objects
        res = self._reqXml('PUT', '/import/links', xml, 400)
        return res.toxml() if hasattr(res, "toxml") else res

    def _s(self, value):
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        return str(value)

    def importIssues(self, projectId, assigneeGroup, issues):
        """ Import issues, returns import result (http://confluence.jetbrains.net/display/YTD2/Import+Issues)
            Accepts retrun of getIssues()
            Example: importIssues([{'numberInProject':'1', 'summary':'some problem', 'description':'some description', 'priority':'1',
                                    'fixedVersion':['1.0', '2.0'],
                                    'comment':[{'author':'yamaxim', 'text':'comment text', 'created':'1267030230127'}]},
                                   {'numberInProject':'2', 'summary':'some problem', 'description':'some description', 'priority':'1'}])
        """
        if len(issues) <= 0:
            return

        bad_fields = ['id', 'projectShortName', 'votes', 'commentsCount',
                      'historyUpdated', 'updatedByFullName', 'updaterFullName',
                      'reporterFullName', 'links', 'attachments', 'jiraId',
                      'entityId', 'tags', 'sprint', 'wikified']

        tt_settings = self.getProjectTimeTrackingSettings(projectId)
        if tt_settings and tt_settings.Enabled and tt_settings.TimeSpentField:
            bad_fields.append(tt_settings.TimeSpentField)

        if not self.isMarkdownSupported():
            bad_fields.append('markdown')

        req_body = ElementTree.Element('issues')
        issue_records = dict([])

        for issue in issues:
            req_issue = ElementTree.Element('issue')

            comments = None
            if getattr(issue, "getComments", None):
                comments = issue.getComments()

            for issueAttr in issue:
                attrValue = issue[issueAttr]
                if attrValue is None:
                    continue
                if issueAttr == 'comments':
                    comments = attrValue
                else:
                    # ignore bad fields from getIssue()
                    if issueAttr not in bad_fields:
                        req_field = ElementTree.SubElement(req_issue, 'field', name=self._s(issueAttr))
                        if isinstance(attrValue, collections.Iterable) \
                                and not isinstance(attrValue, str) \
                                and not isinstance(attrValue, bytes):
                            for v in attrValue:
                                req_value = ElementTree.SubElement(req_field, 'value')
                                req_value.text = self._s(v).strip()
                        else:
                            req_value = ElementTree.SubElement(req_field, 'value')
                            req_value.text = self._s(attrValue).strip()

            if comments:
                for comment in comments:
                    req_comment = ElementTree.SubElement(req_issue, 'comment')
                    for ca in comment:
                        req_comment.set(ca, comment[ca])

            req_body.append(req_issue)
            issue_records[issue.numberInProject] = ElementTree.tostring(req_issue).decode('utf-8')

        # print xml
        # TODO: convert response xml into python objects

        url = '/import/' + urllib.parse.quote(projectId) + '/issues?' + urllib.parse.urlencode(
            {'assigneeGroup': assigneeGroup})
        result = self._reqXml('PUT', url, req_body, 400)
        if (result == "") and (len(issues) > 1):
            for issue in issues:
                self.importIssues(projectId, assigneeGroup, [issue])
        response = ""
        try:
            response = result.toxml()
        except:
            sys.stderr.write("can't parse response\n")
            sys.stderr.write("request was\n")
            sys.stderr.write(ElementTree.tostring(req_body).decode('utf-8') + "\n")
            return response
        item_elements = minidom.parseString(response).getElementsByTagName("item")
        if len(item_elements) != len(issues):
            sys.stderr.write(response + "\n")
            sys.stderr.write("request was\n")
            sys.stderr.write(ElementTree.tostring(req_body).decode('utf-8') + "\n")
        else:
            for item in item_elements:
                id = item.attributes["id"].value
                imported = item.attributes["imported"].value.lower()
                if imported == "true":
                    print("Issue [ %s-%s ] imported successfully" % (projectId, id))
                else:
                    sys.stderr.write("")
                    sys.stderr.write("Failed to import issue [ %s-%s ]." % (projectId, id))
                    sys.stderr.write("Reason : ")
                    sys.stderr.write(item.toxml())
                    sys.stderr.write("Request was :")
                    sys.stderr.write(issue_records[id])
        return response

    def getProjects(self):
        projects = {}
        for e in self._get("/project/all").documentElement.childNodes:
            projects[e.getAttribute('shortName')] = e.getAttribute('name')
        return projects

    def getProject(self, projectId):
        """ http://confluence.jetbrains.net/display/YTD2/GET+project
        """
        return youtrack.Project(self._get("/admin/project/" + urllib.parse.quote(projectId)), self)

    def getProjectIds(self):
        response, content = self._req('GET', '/admin/project/')
        xml = minidom.parseString(content)
        return [e.getAttribute('id') for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getProjectAssigneeGroups(self, projectId):
        response, content = self._req('GET', '/admin/project/' + urllib.parse.quote(projectId) + '/assignee/group')
        xml = minidom.parseString(content)
        return [youtrack.Group(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getGroup(self, name):
        return youtrack.Group(self._get("/admin/group/" + urllib.parse.quote(name)), self)

    def getGroups(self):
        response, content = self._req('GET', '/admin/group')
        xml = minidom.parseString(content)
        return [youtrack.Group(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def deleteGroup(self, name):
        return self._req('DELETE', "/admin/group/" + urllib.parse.quote(name))

    def getUserGroups(self, userName):
        response, content = self._req('GET', '/admin/user/%s/group' % urllib.parse.quote(userName))
        xml = minidom.parseString(content)
        return [youtrack.Group(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def setUserGroup(self, user_name, group_name):
        response, content = self._req('POST',
                                      '/admin/user/%s/group/%s' % (
                                          urllib.parse.quote(user_name), urllib.parse.quote(group_name)),
                                      body='')
        return response

    def createGroup(self, group):
        content = self._put(
            '/admin/group/%s?autoJoin=false' % urllib.parse.quote(group.name))
        return content

    def addUserRoleToGroup(self, group, userRole):
        url_group_name = urllib.parse.quote(group.name)
        url_role_name = urllib.parse.quote(userRole.name)
        response, content = self._req('PUT', '/admin/group/%s/role/%s' % (url_group_name, url_role_name),
                                      body=userRole.toXml())
        return content

    def getRole(self, name):
        return youtrack.Role(self._get("/admin/role/" + urllib.parse.quote(name)), self)

    def getRoles(self):
        response, content = self._req('GET', '/admin/role')
        xml = minidom.parseString(content)
        return [youtrack.Role(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getGroupRoles(self, group_name):
        response, content = self._req('GET', '/admin/group/%s/role' % urllib.parse.quote(group_name))
        xml = minidom.parseString(content)
        return [youtrack.UserRole(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def createRole(self, role):
        url_role_name = urllib.parse.quote(role.name)
        url_role_dscr = ''
        if hasattr(role, 'description'):
            url_role_dscr = urllib.parse.quote(role.description)
        content = self._put('/admin/role/%s?description=%s' % (url_role_name, url_role_dscr))
        return content

    def changeRole(self, role, new_name, new_description):
        url_role_name = urllib.parse.quote(role.name)
        url_new_name = urllib.parse.quote(new_name)
        url_new_dscr = urllib.parse.quote(new_description)
        content = self._req('POST',
                            '/admin/role/%s?newName=%s&description=%s' % (url_role_name, url_new_name, url_new_dscr))
        return content

    def addPermissionToRole(self, role, permission):
        url_role_name = urllib.parse.quote(role.name)
        url_prm_name = urllib.parse.quote(permission.name)
        content = self._req('POST', '/admin/role/%s/permission/%s' % (url_role_name, url_prm_name))
        return content

    def getRolePermissions(self, role):
        response, content = self._req('GET', '/admin/role/%s/permission' % urllib.parse.quote(role.name))
        xml = minidom.parseString(content)
        return [youtrack.Permission(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getPermissions(self):
        response, content = self._req('GET', '/admin/permission')
        xml = minidom.parseString(content)
        return [youtrack.Permission(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getSubsystem(self, projectId, name):
        response, content = self._req('GET', '/admin/project/' + projectId + '/subsystem/' + urllib.parse.quote(name))
        xml = minidom.parseString(content)
        return youtrack.Subsystem(xml, self)

    def getSubsystems(self, projectId):
        response, content = self._req('GET', '/admin/project/' + projectId + '/subsystem')
        xml = minidom.parseString(content)
        return [youtrack.Subsystem(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getVersions(self, projectId):
        response, content = self._req('GET',
                                      '/admin/project/' + urllib.parse.quote(projectId) + '/version?showReleased=true')
        xml = minidom.parseString(content)
        return [self.getVersion(projectId, v.getAttribute('name')) for v in
                xml.documentElement.getElementsByTagName('version')]

    def getVersion(self, projectId, name):
        return youtrack.Version(
            self._get("/admin/project/" + urllib.parse.quote(projectId) + "/version/" + urllib.parse.quote(name)), self)

    def getBuilds(self, projectId):
        response, content = self._req('GET', '/admin/project/' + urllib.parse.quote(projectId) + '/build')
        xml = minidom.parseString(content)
        return [youtrack.Build(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getUsers(self, params={}):
        first = True
        users = []
        position = 0
        user_search_params = urllib.parse.urlencode(params)
        while True:
            response, content = self._req('GET', "/admin/user/?start=%s&%s" % (str(position), user_search_params))
            position += 10
            xml = minidom.parseString(content)
            newUsers = [youtrack.User(e, self) for e in xml.documentElement.childNodes if
                        e.nodeType == Node.ELEMENT_NODE]
            if not len(newUsers): return users
            users += newUsers

    def getUsersTen(self, start):
        response, content = self._req('GET', "/admin/user/?start=%s" % str(start))
        xml = minidom.parseString(content)
        users = [youtrack.User(e, self) for e in xml.documentElement.childNodes if
                 e.nodeType == Node.ELEMENT_NODE]
        return users

    def deleteUser(self, login):
        return self._req('DELETE', "/admin/user/" + urllib.parse.quote(login))

    # TODO this function is deprecated
    def createBuild(self):
        raise NotImplementedError

    # TODO this function is deprecated
    def createBuilds(self):
        raise NotImplementedError

    def createProject(self, project):
        return self.createProjectDetailed(project.id, project.name, project.description, project.lead)

    def deleteProject(self, projectId):
        return self._req('DELETE', "/admin/project/" + urllib.parse.quote(projectId))

    def createProjectDetailed(self, projectId, name, description, projectLeadLogin, startingNumber=1):
        _name = name
        _desc = description
        _name = _name.replace('/', ' ')
        return self._put('/admin/project/' + projectId + '?' +
                         urllib.parse.urlencode({'projectName': _name,
                                                 'description': _desc + ' ',
                                                 'projectLeadLogin': projectLeadLogin,
                                                 'lead': projectLeadLogin,
                                                 'startingNumber': str(startingNumber)}))

    # TODO this function is deprecated
    def createSubsystems(self, projectId, subsystems):
        """ Accepts result of getSubsystems()
        """

        for s in subsystems:
            self.createSubsystem(projectId, s)

    # TODO this function is deprecated
    def createSubsystem(self, projectId, s):
        return self.createSubsystemDetailed(projectId, s.name, s.isDefault,
                                            s.defaultAssignee if s.defaultAssignee != '<no user>' else '')

    # TODO this function is deprecated
    def createSubsystemDetailed(self, projectId, name, isDefault, defaultAssigneeLogin):
        self._put('/admin/project/' + projectId + '/subsystem/' + urllib.parse.quote(name) + "?" +
                  urllib.parse.urlencode({'isDefault': str(isDefault),
                                          'defaultAssignee': defaultAssigneeLogin}))

        return 'Created'

    # TODO this function is deprecated
    def deleteSubsystem(self, projectId, name):
        return self._reqXml('DELETE',
                            '/admin/project/' + projectId + '/subsystem/' + urllib.parse.quote(name)
                            , '')

    # TODO this function is deprecated
    def createVersions(self, projectId, versions):
        """ Accepts result of getVersions()
        """

        for v in versions:
            self.createVersion(projectId, v)

    # TODO this function is deprecated
    def createVersion(self, projectId, v):
        return self.createVersionDetailed(projectId, v.name, v.isReleased, v.isArchived, releaseDate=v.releaseDate,
                                          description=v.description)

    # TODO this function is deprecated
    def createVersionDetailed(self, projectId, name, isReleased, isArchived, releaseDate=None, description=''):
        params = {'description': description,
                  'isReleased': str(isReleased),
                  'isArchived': str(isArchived)}
        if releaseDate is not None:
            params['releaseDate'] = str(releaseDate)
        return self._put(
            '/admin/project/' + urllib.parse.quote(projectId) + '/version/' + urllib.parse.quote(name) + "?" +
            urllib.parse.urlencode(params))

    def getIssues(self, projectId, filter, after, max):
        # response, content = self._req('GET', '/project/issues/' + urllib.parse.quote(projectId) + "?" +
        path = '/issue'
        if projectId:
            path += '/byproject/' + urllib.parse.quote(projectId)
        response, content = self._req('GET', path + "?" +
                                      urllib.parse.urlencode({'after': str(after),
                                                              'max': str(max),
                                                              'filter': filter}))
        xml = minidom.parseString(content)
        return [youtrack.Issue(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getNumberOfIssues(self, filter='', waitForServer=True):
        while True:
            urlFilterList = [('filter', filter)]
            finalUrl = '/issue/count?' + urllib.parse.urlencode(urlFilterList)
            response, content = self._req('GET', finalUrl, content_type="application/json")
            result = json.loads(content)
            numberOfIssues = result['value']
            if (not waitForServer):
                return numberOfIssues
            if (numberOfIssues != -1):
                break

        time.sleep(5)
        return self.getNumberOfIssues(filter, False)

    def getAllSprints(self, agileID):
        response, content = self._req('GET', '/agile/' + agileID + "/sprints?")
        xml = minidom.parseString(content)
        return [(e.getAttribute('name'), e.getAttribute('start'), e.getAttribute('finish')) for e in
                xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def getAllIssues(self, filter='', after=0, max=999999, withFields=()):
        urlJobby = [('with', field) for field in withFields] + \
                   [('after', str(after)),
                    ('max', str(max)),
                    ('filter', filter)]
        response, content = self._req('GET', '/issue' + "?" +
                                      urllib.parse.urlencode(urlJobby))
        xml = minidom.parseString(content)
        return [youtrack.Issue(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def exportIssueLinks(self):
        response, content = self._req('GET', '/export/links')
        xml = minidom.parseString(content)
        return [youtrack.Link(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def executeCommand(self, issueId, command, comment=None, group=None, run_as=None, disable_notifications=False):
        params = {'command': command}

        if comment is not None:
            params['comment'] = comment

        if group is not None:
            params['group'] = group

        if run_as is not None:
            params['runAs'] = run_as

        if disable_notifications:
            params['disableNotifications'] = disable_notifications

        self._req('POST',
                  '/issue/' + issueId + "/execute",
                  body=urllib.parse.urlencode(params),
                  content_type='application/x-www-form-urlencoded')

        return "Command executed"

    def getCustomField(self, name):
        return youtrack.CustomField(self._get("/admin/customfield/field/" + urllib.parse.quote(name)),
                                    self)

    def getCustomFields(self):
        response, content = self._req('GET', '/admin/customfield/field')
        xml = minidom.parseString(content)
        return [self.getCustomField(e.getAttribute('name')) for e in xml.documentElement.childNodes if
                e.nodeType == Node.ELEMENT_NODE]

    def createCustomField(self, cf):
        params = dict([])
        if hasattr(cf, "defaultBundle"):
            params["defaultBundle"] = cf.defaultBundle
        if hasattr(cf, "attachBundlePolicy"):
            params["attachBundlePolicy"] = cf.attachBundlePolicy
        auto_attached = False
        if hasattr(cf, "autoAttached"):
            auto_attached = cf.autoAttached
        return self.createCustomFieldDetailed(cf.name, cf.type, cf.isPrivate, cf.visibleByDefault, auto_attached,
                                              params)

    def createCustomFieldDetailed(self, customFieldName, typeName, isPrivate, defaultVisibility,
                                  auto_attached=False, additional_params=dict([])):
        params = {'type': typeName, 'isPrivate': str(isPrivate), 'defaultVisibility': str(defaultVisibility),
                  'autoAttached': str(auto_attached)}
        params.update(additional_params)

        self._put('/admin/customfield/field/' + urllib.parse.quote(customFieldName) + '?' +
                  urllib.parse.urlencode(params), )

        return "Created"

    def createCustomFields(self, cfs):
        for cf in cfs:
            self.createCustomField(cf)

    def getProjectCustomField(self, projectId, name):
        return youtrack.ProjectCustomField(
            self._get("/admin/project/" + urllib.parse.quote(projectId) + "/customfield/" + urllib.parse.quote(name))
            , self)

    def getProjectCustomFields(self, projectId):
        response, content = self._req('GET', '/admin/project/' + urllib.parse.quote(projectId) + '/customfield')
        xml = minidom.parseString(content)
        return [self.getProjectCustomField(projectId, e.getAttribute('name')) for e in
                xml.getElementsByTagName('projectCustomField')]

    def createProjectCustomField(self, projectId, pcf):
        return self.createProjectCustomFieldDetailed(projectId, pcf.name, pcf.emptyText, pcf.params)

    def createProjectCustomFieldDetailed(self, projectId, customFieldName, emptyFieldText, params=None):
        if not len(emptyFieldText.strip()):
            emptyFieldText = "No " + customFieldName
        _params = {'emptyFieldText': emptyFieldText}
        if params is not None:
            _params.update(params)
        return self._put(
            '/admin/project/' + projectId + '/customfield/' + urllib.parse.quote(customFieldName) + '?' +
            urllib.parse.urlencode(_params))

    def deleteProjectCustomField(self, project_id, pcf_name):
        self._req('DELETE',
                  '/admin/project/' + urllib.parse.quote(project_id) + "/customfield/" + urllib.parse.quote(pcf_name))

    def getIssueLinkTypes(self):
        response, content = self._req('GET', '/admin/issueLinkType')
        xml = minidom.parseString(content)
        return [youtrack.IssueLinkType(e, self) for e in xml.getElementsByTagName('issueLinkType')]

    def createIssueLinkTypes(self, issueLinkTypes):
        for ilt in issueLinkTypes:
            return self.createIssueLinkType(ilt)

    def createIssueLinkType(self, ilt):
        return self.createIssueLinkTypeDetailed(ilt.name, ilt.outwardName, ilt.inwardName, ilt.directed)

    def createIssueLinkTypeDetailed(self, name, outwardName, inwardName, directed):
        return self._put('/admin/issueLinkType/' + urllib.parse.quote(name) + '?' +
                         urllib.parse.urlencode({'outwardName': outwardName,
                                                 'inwardName': inwardName,
                                                 'directed': directed}))

    def getEvents(self, issue_id):
        return self._get('/event/issueEvents/' + urllib.parse.quote(issue_id))

    # def getTags(self, issue_id):
    #     return self._get('/event/issueEvents/' + urllib.parse.quote(issue_id))

    def getTag(self, name):
        response, content = self._req('GET', '/user/tag/' + urllib.parse.quote(name))
        xml = minidom.parseString(content)
        return youtrack.Subsystem(xml, self)

    def getTags(self):
        xml = self._reqXml('GET', '/user/tag')
        return [youtrack.Tag(e, self) for e in xml.documentElement.childNodes if e.nodeType == Node.ELEMENT_NODE]

    def createTags(self, tags):
        """ Accepts result of getTags()
        """

        for s in tags:
            self.createTag(s)

    def createTag(self, s):
        return self.createTagDetailed(s.name, s.untagOnResolve, s.visibleForGroup, s.updatableByGroup)

    def createTagDetailed(self, name, untagOnResolve=False, visibleForGroup=None, updatableByGroup=None):
        params = {
            'visibleForGroup': visibleForGroup,
            'updatableByGroup': updatableByGroup,
            'untagOnResolve': untagOnResolve
        }
        params = {key: value for (key, value) in params.items() if value is not None}
        self._put('/user/tag/%s?%s' % (urllib.parse.quote(name), urllib.parse.urlencode(params)))

        return 'Created'

    def deleteTag(self, name):
        return self._reqXml('DELETE', '/user/tag/' + urllib.parse.quote(name), '')

    def getWorkItems(self, issue_id):
        try:
            response, content = self._req('GET',
                                          '/issue/%s/timetracking/workitem' % urllib.parse.quote(issue_id),
                                          content_type="application/xml")
            xml = minidom.parseString(content)
            return [youtrack.WorkItem(e, self) for e in xml.documentElement.childNodes if
                    e.nodeType == Node.ELEMENT_NODE]
        except youtrack.YouTrackException as e:
            print("Can't get work items.", str(e))
            return []

    def createWorkItem(self, issue_id, work_item):
        xml = '<workItem>'
        xml += '<date>%s</date>' % work_item.date
        xml += '<duration>%s</duration>' % work_item.duration
        if hasattr(work_item, 'description') and work_item.description is not None:
            xml += '<description>%s</description>' % escape(work_item.description)
        if hasattr(work_item, 'worktype') and work_item.worktype is not None:
            xml += '<worktype><name>%s</name></worktype>' % work_item.worktype
        xml += '</workItem>'
        self._reqXml('POST',
                     '/issue/%s/timetracking/workitem' % urllib.parse.quote(issue_id), xml)

    def importWorkItems(self, issue_id, work_items):
        xml = ''
        for work_item in work_items:
            xml += '<workItem>'
            xml += '<date>%s</date>' % work_item.date
            xml += '<duration>%s</duration>' % work_item.duration
            if hasattr(work_item, 'description') and work_item.description is not None:
                xml += '<description>%s</description>' % escape(work_item.description)
            if hasattr(work_item, 'worktype') and work_item.worktype is not None:
                xml += '<worktype><name>%s</name></worktype>' % work_item.worktype
            xml += '<author login=%s></author>' % quoteattr(work_item.authorLogin)
            xml += '</workItem>'
        if xml:
            xml = '<workItems>' + xml + '</workItems>'
            try:
                self.headers['Accept'] = 'application/xml'
                self._reqXml(
                    'PUT',
                    '/import/issue/%s/workitems' % urllib.parse.quote(issue_id), xml)
            finally:
                del self.headers['Accept']

    def getSearchIntelliSense(self, query,
                              context=None, caret=None, options_limit=None):
        opts = {'filter': query}
        if context:
            opts['project'] = context
        if caret is not None:
            opts['caret'] = caret
        if options_limit is not None:
            opts['optionsLimit'] = options_limit
        return youtrack.IntelliSense(
            self._get('/issue/intellisense?' + urllib.parse.urlencode(opts)), self)

    def getCommandIntelliSense(self, issue_id, command,
                               run_as=None, caret=None, options_limit=None):
        opts = {'command': command}
        if run_as:
            opts['runAs'] = run_as
        if caret is not None:
            opts['caret'] = caret
        if options_limit is not None:
            opts['optionsLimit'] = options_limit
        return youtrack.IntelliSense(
            self._get('/issue/%s/execute/intellisense?%s'
                      % (issue_id, urllib.parse.urlencode(opts))), self)

    def getGlobalTimeTrackingSettings(self):
        try:
            cont = self._get('/admin/timetracking')
            return youtrack.GlobalTimeTrackingSettings(cont, self)
        except youtrack.YouTrackException as e:
            if e.response.status != 404:
                raise e

    def getProjectTimeTrackingSettings(self, projectId):
        try:
            cont = self._get('/admin/project/' + projectId + '/timetracking')
            return youtrack.ProjectTimeTrackingSettings(cont, self)
        except youtrack.YouTrackException as e:
            if e.response.status != 404:
                raise e

    def setGlobalTimeTrackingSettings(self, daysAWeek=None, hoursADay=None):
        xml = '<timesettings>'
        if daysAWeek is not None:
            xml += '<daysAWeek>%d</daysAWeek>' % daysAWeek
        if hoursADay is not None:
            xml += '<hoursADay>%d</hoursADay>' % hoursADay
        xml += '</timesettings>'
        return self._reqXml('PUT', '/admin/timetracking', xml)

    def setProjectTimeTrackingSettings(self,
                                       projectId, estimateField=None, timeSpentField=None, enabled=None):
        if enabled is not None:
            xml = '<settings enabled="%s">' % str(enabled == True).lower()
        else:
            xml = '<settings>'
        if estimateField is not None and estimateField != '':
            xml += '<estimation name="%s"/>' % estimateField
        if timeSpentField is not None and timeSpentField != '':
            xml += '<spentTime name="%s"/>' % timeSpentField
        xml += '</settings>'
        return self._reqXml(
            'PUT', '/admin/project/' + projectId + '/timetracking', xml)

    def get_work_types(self, project_id=None):
        if project_id:
            path = '/admin/project/%s/timetracking/worktype' % project_id
        else:
            path = '/admin/timetracking/worktype'
        try:
            xml = self._get(path)
            return [youtrack.WorkType(e, self)
                    for e in xml.documentElement.childNodes
                    if e.nodeType == Node.ELEMENT_NODE]
        except youtrack.YouTrackException as e:
            print(("Can't get work types", str(e)))
            return []

    def create_work_type(self, name=None, auto_attached=None, work_type=None):
        if work_type:
            wt = work_type
        else:
            if not name:
                raise ValueError("Work type name cannot be empty")
            wt = youtrack.WorkType()
            wt.name = name
            wt.autoAttached = auto_attached
        response, content = self._req(
            'POST', '/admin/timetracking/worktype', wt.toXml())
        return youtrack.WorkType(self._get(response['location']))

    def create_work_type_safe(self,
                              name=None, auto_attached=None, work_type=None):
        try:
            return self.create_work_type(name, auto_attached, work_type)
        except youtrack.YouTrackException as e:
            # Assume that this caused by not unique value and try to find
            # original work type
            if e.response.status not in (400, 409):
                raise e
            if work_type:
                name_lc = work_type.name.lower()
            else:
                name_lc = name.lower()
            for wt in self.get_work_types():
                if wt.name.lower() == name_lc:
                    return wt
            raise e

    def attach_work_type_to_project(self, project_id, work_type_id):
        self._req('PUT',
                  '/admin/project/%s/timetracking/worktype/%s' %
                  (project_id, work_type_id))

    def create_project_work_type(
            self, project_id, name=None, auto_attached=None, work_type=None):
        wt = self.create_work_type_safe(name, auto_attached, work_type)
        self.attach_work_type_to_project(project_id, wt.id)

    def getAllBundles(self, field_type):
        field_type = self.get_field_type(field_type)
        if field_type == "enum":
            tag_name = "enumFieldBundle"
        elif field_type == "user":
            tag_name = "userFieldBundle"
        else:
            tag_name = self.bundle_paths[field_type]
        names = [e.getAttribute("name") for e in self._get('/admin/customfield/' +
                                                           self.bundle_paths[field_type]).getElementsByTagName(
            tag_name)]
        return [self.getBundle(field_type, name) for name in names]

    def get_field_type(self, field_type):
        if "[" in field_type:
            field_type = field_type[0:-3]
        return field_type

    def getBundle(self, field_type, name):
        field_type = self.get_field_type(field_type)
        response = self._get('/admin/customfield/%s/%s' % (self.bundle_paths[field_type], urllib.parse.quote(name)))
        return self.bundle_types[field_type](response, self)

    def renameBundle(self, bundle, new_name):
        response, content = self._req("POST", "/admin/customfield/%s/%s?newName=%s" % (
            self.bundle_paths[bundle.get_field_type()], bundle.name, new_name), "", ignoreStatus=301)
        return response

    def createBundle(self, bundle):
        return self._reqXml('PUT', '/admin/customfield/' + self.bundle_paths[bundle.get_field_type()],
                            body=bundle.toXml(), ignoreStatus=400)

    def deleteBundle(self, bundle):
        response, content = self._req("DELETE", "/admin/customfield/%s/%s" % (
            self.bundle_paths[bundle.get_field_type()], bundle.name), "")
        return response

    def addValueToBundle(self, bundle, value):
        request = ""
        if bundle.get_field_type() != "user":
            request = "/admin/customfield/%s/%s/" % (
                self.bundle_paths[bundle.get_field_type()], urllib.parse.quote(bundle.name))
            if isinstance(value, str):
                request += urllib.parse.quote(value)
            else:
                request += urllib.parse.quote(value.name) + "?"
                params = dict()
                for e in value:
                    if (e != "name") and (e != "element_name") and len(value[e]):
                        params[e] = value[e]
                if len(params):
                    request += urllib.parse.urlencode(params)
        else:
            request = "/admin/customfield/userBundle/%s/" % urllib.parse.quote(bundle.name)
            if isinstance(value, youtrack.User):
                request += "individual/%s/" % value.login
            elif isinstance(value, youtrack.Group):
                request += "group/%s/" % urllib.parse.quote(value.name)
            else:
                request += "individual/%s/" % urllib.parse.quote(value)
        return self._put(request)

    def removeValueFromBundle(self, bundle, value):
        field_type = bundle.get_field_type()
        request = "/admin/customfield/%s/%s/" % (self.bundle_paths[field_type], bundle.name)
        if field_type != "user":
            request += urllib.parse.quote(value.name)
        elif isinstance(value, youtrack.User):
            request += "individual/" + urllib.parse.quote(value.login)
        else:
            request += "group/" + value.name
        response, content = self._req("DELETE", request, "", ignoreStatus=204)
        return response

    def getEnumBundle(self, name):
        return youtrack.EnumBundle(self._get("/admin/customfield/bundle/" + urllib.parse.quote(name)), self)

    def createEnumBundle(self, eb):
        return self.createBundle(eb)

    def deleteEnumBundle(self, name):
        return self.deleteBundle(self.getEnumBundle(name))

    def createEnumBundleDetailed(self, name, values):
        xml = '<enumeration name=\"' + name + '\">'
        xml += ' '.join('<value>' + v + '</value>' for v in values)
        xml += '</enumeration>'
        return self._reqXml('PUT', '/admin/customfield/bundle', body=xml, ignoreStatus=400)

    def addValueToEnumBundle(self, name, value):
        return self.addValueToBundle(self.getEnumBundle(name), value)

    def addValuesToEnumBundle(self, name, values):
        return ", ".join(self.addValueToEnumBundle(name, value) for value in values)

    def getYouTrackBuildNumber(self):
        response, content = self._req('GET',
                                      self.url + '/api/config?fields=build',
                                      ignoreStatus=404,
                                      content_type='application/json')
        if response.status != 200 or not content:
            return 0
        try:
            return int(json.loads(content).get('build', 0))
        except ValueError:
            return 0

    def getYouTrackVersionNumber(self):
        response, content = self._req('GET',
                                      self.url + '/api/config?fields=version',
                                      ignoreStatus=404,
                                      content_type='application/json')
        if response.status != 200 or not content:
            return 0
        try:
            return float(json.loads(content).get('version', 0))
        except ValueError:
            return 0

    def isMarkdownSupported(self):
        return self.getYouTrackVersionNumber() >= 2019.1

    bundle_paths = {
        "enum": "bundle",
        "build": "buildBundle",
        "ownedField": "ownedFieldBundle",
        "state": "stateBundle",
        "version": "versionBundle",
        "user": "userBundle"
    }

    bundle_types = {
        "enum": lambda xml, yt: youtrack.EnumBundle(xml, yt),
        "build": lambda xml, yt: youtrack.BuildBundle(xml, yt),
        "ownedField": lambda xml, yt: youtrack.OwnedFieldBundle(xml, yt),
        "state": lambda xml, yt: youtrack.StateBundle(xml, yt),
        "version": lambda xml, yt: youtrack.VersionBundle(xml, yt),
        "user": lambda xml, yt: youtrack.UserBundle(xml, yt)
    }
