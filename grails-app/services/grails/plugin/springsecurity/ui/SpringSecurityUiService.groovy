/* Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity.ui

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.authentication.dao.NullSaltSource
import grails.plugin.springsecurity.ui.strategy.AclStrategy
import grails.plugin.springsecurity.ui.strategy.ErrorsStrategy
import grails.plugin.springsecurity.ui.strategy.MailStrategy
import grails.plugin.springsecurity.ui.strategy.PersistentLoginStrategy
import grails.plugin.springsecurity.ui.strategy.PropertiesStrategy
import grails.plugin.springsecurity.ui.strategy.QueryStrategy
import grails.plugin.springsecurity.ui.strategy.RegistrationCodeStrategy
import grails.plugin.springsecurity.ui.strategy.RequestmapStrategy
import grails.plugin.springsecurity.ui.strategy.RoleStrategy
import grails.plugin.springsecurity.ui.strategy.UserStrategy
import grails.transaction.Transactional
import grails.util.GrailsNameUtils
import groovy.util.logging.Slf4j

import java.text.SimpleDateFormat

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.context.MessageSource
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.security.authentication.dao.SaltSource
import org.springframework.security.core.userdetails.UserCache
import org.springframework.transaction.TransactionStatus
import org.springframework.util.ClassUtils

/**
 * Helper methods for UI management.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@Slf4j
class SpringSecurityUiService implements AclStrategy, ErrorsStrategy, PersistentLoginStrategy,
                                         PropertiesStrategy, QueryStrategy, RegistrationCodeStrategy,
                                         RequestmapStrategy, RoleStrategy, UserStrategy {

	public static final String DATE_FORMAT = 'd MMM yyyy HH:mm:ss'

	protected static final String ACL_CLASS_NAME           = 'grails.plugin.springsecurity.acl.AclClass'
	protected static final String ACL_ENTRY_NAME           = 'grails.plugin.springsecurity.acl.AclEntry'
	protected static final String ACL_OBJECT_IDENTITY_NAME = 'grails.plugin.springsecurity.acl.AclObjectIdentity'
	protected static final String ACL_SID_NAME             = 'grails.plugin.springsecurity.acl.AclSid'

	protected Map<Class<?>, Map<String, String>> classMappings

	/** Dependency injection for the 'uiErrorsStrategy' bean. */
	ErrorsStrategy uiErrorsStrategy

	/** Dependency injection for the 'uiMailStrategy' bean. */
	MailStrategy uiMailStrategy

	/** Dependency injection for the 'uiPropertiesStrategy' bean. */
	PropertiesStrategy uiPropertiesStrategy

	GrailsApplication grailsApplication
	MessageSource messageSource
	SaltSource saltSource
	def springSecurityService
	UserCache userCache

	@Transactional
	def saveAclClass(Map properties) {
		save properties, AclClass, 'saveAclClass', transactionStatus
	}

	@Transactional
	void updateAclClass(Map properties, aclClass) {
		save properties, aclClass, 'updateAclClass', transactionStatus
	}

	@Transactional
	void deleteAclClass(aclClass) {
		// will fail if there are FK references
		delete aclClass, 'deleteAclClass', transactionStatus
	}

	@Transactional
	def saveAclEntry(Map properties) {
		save(properties, AclEntry, 'saveAclEntry', transactionStatus) { aclEntry ->
			removeIfTransient aclEntry, 'aclObjectIdentity', 'sid'
		}
	}

	@Transactional
	void updateAclEntry(Map properties, aclEntry) {
		save(properties, aclEntry, 'updateAclEntry', transactionStatus) {
			removeIfTransient aclEntry, 'aclObjectIdentity', 'sid'
		}
	}

	@Transactional
	void deleteAclEntry(aclEntry) {
		delete aclEntry, 'deleteAclEntry', transactionStatus
	}

	@Transactional
	def saveAclObjectIdentity(Map properties) {
		save(properties, AclObjectIdentity, 'saveAclObjectIdentity', transactionStatus) { aclObjectIdentity ->
			removeIfTransient aclObjectIdentity, 'aclClass', 'owner', 'parent'
		}
	}

	@Transactional
	void updateAclObjectIdentity(Map properties, aclObjectIdentity) {
		save properties, aclObjectIdentity, 'updateAclObjectIdentity', transactionStatus
	}

	@Transactional
	void deleteAclObjectIdentity(aclObjectIdentity) {
		// will fail if there are FK references
		delete aclObjectIdentity, 'deleteAclObjectIdentity', transactionStatus
	}

	@Transactional
	def saveAclSid(Map properties) {
		save properties, AclSid, 'saveAclSid', transactionStatus
	}

	@Transactional
	void updateAclSid(Map properties, aclSid) {
		save properties, aclSid, 'updateAclSid', transactionStatus
	}

	@Transactional
	void deleteAclSid(aclSid) {
		// will fail if there are FK references
		delete aclSid, 'deleteAclSid', transactionStatus
	}

	@Transactional
	void updatePersistentLogin(Map properties, persistentLogin) {
		properties = [:] + properties
		if (properties.lastUsed && properties.lastUsed instanceof String) {
			Calendar c = Calendar.instance
			c.time = new SimpleDateFormat(DATE_FORMAT).parse(properties.lastUsed)
			properties.lastUsed = c.time
		}

		save properties, persistentLogin, 'updatePersistentLogin', transactionStatus
	}

	@Transactional
	void deletePersistentLogin(persistentLogin) {
		delete persistentLogin, 'deletePersistentLogin', transactionStatus
	}

	@Transactional
	void updateRegistrationCode(Map properties, RegistrationCode registrationCode) {
		save properties, registrationCode, 'updateRegistrationCode', transactionStatus
	}

	@Transactional
	void deleteRegistrationCode(RegistrationCode registrationCode) {
		delete registrationCode, 'deleteRegistrationCode', transactionStatus
	}

	@Transactional
	RegistrationCode register(user, String password, salt) {

		save password: encodePassword(password, salt), user, 'register', transactionStatus
		if (user.hasErrors()) {
			return
		}

		String username = uiPropertiesStrategy.getProperty(user, 'username')
		save username: username, RegistrationCode, 'register', transactionStatus
	}

	def createUser(RegisterCommand command) {
		uiPropertiesStrategy.setProperties(
			email: command.email, username: command.username, accountLocked: true, enabled: true, User, null)
	}

	@Transactional
	def finishRegistration(RegistrationCode registrationCode) {

		def user = findUserByUsername(registrationCode.username)
		if (!user) {
			return
		}

		save accountLocked: false, user, 'finishRegistration', transactionStatus
		if (!user.hasErrors()) {
			addRoles user, registerDefaultRoleNames, transactionStatus
			delete registrationCode, 'finishRegistration', transactionStatus
			springSecurityService.reauthenticate registrationCode.username
		}

		user
	}

	@Transactional
	RegistrationCode sendForgotPasswordMail(String username, String emailAddress,
	                                        Closure emailBodyGenerator) {

		RegistrationCode registrationCode = save(username: username, RegistrationCode,
			'sendForgotPasswordMail', transactionStatus)
		if (!registrationCode.hasErrors()) {
			String body = emailBodyGenerator(registrationCode.token)
			uiMailStrategy.sendForgotPasswordMail(to: emailAddress, from: forgotPasswordEmailFrom,
		                                         subject: forgotPasswordEmailSubject, html: body)
		}

		registrationCode
	}

	@Transactional
	def resetPassword(ResetPasswordCommand command, RegistrationCode registrationCode) {

		String salt = saltSource instanceof NullSaltSource ? null : registrationCode.username
		def user = findUserByUsername(registrationCode.username)
		save password: encodePassword(command.password, salt), user, 'resetPassword', transactionStatus

		if (!user.hasErrors()) {
			delete registrationCode, 'resetPassword', transactionStatus
			springSecurityService.reauthenticate registrationCode.username
		}

		user
	}

	@Transactional
	def saveRole(Map properties) {
		save properties, Role, 'saveRole', transactionStatus
	}

	@Transactional
	void updateRole(Map properties, role) {

		updateKeys properties, role

		try {
			springSecurityService.updateRole role, properties
		}
		catch (e) {
			uiErrorsStrategy.handleException e, role, properties, this, 'updateRole', transactionStatus
			return
		}

		if (role.hasErrors()) {
			uiErrorsStrategy.handleValidationErrors role, this, 'updateRole', transactionStatus
		}
	}

	@Transactional
	void deleteRole(role) {
		try {
			UserRole.removeAll role
			springSecurityService.deleteRole role
		}
		catch (e) {
			uiErrorsStrategy.handleException e, role, null, this, 'deleteRole', transactionStatus
		}
	}

	@Transactional
	def saveRequestmap(Map properties) {
		save properties, Requestmap, 'saveRequestmap', transactionStatus
	}

	@Transactional
	void updateRequestmap(Map properties, requestmap) {

		save properties, requestmap, 'updateRequestmap', transactionStatus

		if (!requestmap.hasErrors()) {
			springSecurityService.clearCachedRequestmaps()
		}
	}

	@Transactional
	void deleteRequestmap(requestmap) {
		delete requestmap, 'deleteRequestmap', transactionStatus
		springSecurityService.clearCachedRequestmaps()
	}

	@Transactional
	def saveUser(Map properties, List<String> roleNames, String password) {

		def user = uiPropertiesStrategy.setProperties(properties, User, transactionStatus)

		if (password) {
			updatePassword user, password, transactionStatus
		}

		save [:], user, 'saveUser', transactionStatus
		if (!user.hasErrors()) {
			addRoles user, roleNames, transactionStatus
		}

		user
	}

	@Transactional
	void updateUser(Map properties, user, List<String> roleNames) {
		String oldPassword = uiPropertiesStrategy.getProperty(user, 'password')

		uiPropertiesStrategy.setProperties properties, user, transactionStatus
		if (properties.password && properties.password != oldPassword) {
			updatePassword user, properties.password, transactionStatus
		}

		save [:], user, 'updateUser', transactionStatus
		if (user.hasErrors()) {
			return
		}

		UserRole.removeAll user
		addRoles user, roleNames, transactionStatus
		removeUserFromCache user
	}

	@Transactional
	void deleteUser(user) {
		UserRole.removeAll user
		delete user, 'deleteUser', transactionStatus
		removeUserFromCache user
	}

	protected void addRoles(user, List<String> roleNames, TransactionStatus transactionStatus) {
		String authorityNameField = uiPropertiesStrategy.paramNameToPropertyName('authority', 'role')

		try {
			for (String roleName in roleNames) {
				UserRole.create user, Role.findWhere((authorityNameField): roleName)
			}
		}
		catch (e) {
			uiErrorsStrategy.handleException e, user, null, this, 'addRoles', transactionStatus
		}
	}

	protected void removeUserFromCache(user) {
		userCache.removeUserFromCache uiPropertiesStrategy.getProperty(user, 'username')
	}

	protected void delete(instance, String methodName, TransactionStatus transactionStatus) {

		assert transactionStatus

		try {
			instance.delete()
		}
		catch (e) {
			uiErrorsStrategy.handleException e, instance, null, this, methodName, transactionStatus
		}
	}

	Map<Class<?>, Map<String, String>> findClassMappings() {
		def conf = SpringSecurityUtils.securityConfig

		def mappings = [:]

		def userLookup = conf.userLookup
		mappings[User] = [
			username:        userLookup.usernamePropertyName ?: '',
			enabled:         userLookup.enabledPropertyName ?: '',
			password:        userLookup.passwordPropertyName ?: '',
			authorities:     userLookup.authoritiesPropertyName ?: '',
			accountExpired:  userLookup.accountExpiredPropertyName ?: '',
			accountLocked:   userLookup.accountLockedPropertyName ?: '',
			passwordExpired: userLookup.passwordExpiredPropertyName ?: ''].asImmutable()

		mappings[Role] = [authority: conf.authority.nameField ?: ''].asImmutable()

		def requestMap = conf.requestMap
		mappings[Requestmap] = [
			url:             requestMap.urlField ?: '',
			configAttribute: requestMap.configAttributeField ?: '',
			httpMethod:      requestMap.httpMethodField ?: ''].asImmutable()

		mappings
	}

	def getProperty(instance, String paramName) {
		if (!instance) return

		if (paramName.endsWith('.id')) {
			paramName = paramName[0..-4]
		}

		def value = instance
		String currentPath = ''
		for (String paramNamePart in paramName.split('\\.')) {
			currentPath += paramNamePart

			String classPropertyName = GrailsNameUtils.getPropertyName(
				unproxy(value.getClass()).name)

			String propertyName = uiPropertiesStrategy.paramNameToPropertyName(
				paramNamePart, classPropertyName)

			try {
				if (instance.metaClass.getMetaProperty(propertyName)?.getter) {
					value = value[propertyName]
					if (value == null) return
				}
				else {
					log.error "Attempted to read non-existent property $currentPath in $instance"
					return
				}
			}
			catch (e) {
				throw new InvalidValueException(propertyName, paramNamePart, value, e)
			}

			currentPath += '.'
		}

		value
	}

	String paramNameToPropertyName(String paramName, String controllerName) {
		// Properties in the ACL classes and RegistrationCode aren't currently
		// configurable, and the PersistentLogin class is generated but its
		// properties also aren't configurable. Since this method is only by
		// the controllers to be able to hard-code param names and lookup the
		// actual domain class property name we can short-circuit the logic here.
		// Additionally there's no need to support nested properties (e.g.
		// 'aclClass.className' for AclObjectIdentity search) since those are
		// not used in GSP for classes with configurable properties.

		if (!paramName) {
			return paramName
		}

		Class<?> clazz = domainClassesByControllerName[controllerName]
		String name
		if (clazz) {
			String key = paramName
			if (paramName.endsWith('.id')) {
				key = paramName[0..-4]
			}
			name = classMappings[clazz][key]
		}
		name ?: paramName
	}

	def setProperties(Map data, instanceOrClass, TransactionStatus transactionStatus) {
		if (instanceOrClass == null) return

		updateKeys data, instanceOrClass

		def instance
		try {
			if (instanceOrClass instanceof Class) {
				instance = instanceOrClass.newInstance(data)
			}
			else {
				instance = instanceOrClass
				instance.properties = data
			}
		}
		catch (e) {
			uiErrorsStrategy.handleException e, instance, data, this, 'setProperties', transactionStatus
		}

		instance
	}

	protected void updateKeys(Map data, instanceOrClass) {
		Class clazz
		if (instanceOrClass instanceof Class) {
			clazz = instanceOrClass
		}
		else {
			clazz = instanceOrClass.getClass()
		}

		Map<String, String> mappings = classMappings[unproxy(clazz)]
		if (!mappings) return

		def removed = [:]
		([] + data.keySet()).each { String paramName ->
			String mappedKey = mappings[paramName]
			if (mappedKey && mappedKey != paramName) {
				removed[mappedKey] = data.remove(paramName)
			}
		}
		data.putAll removed
	}

	void handleValidationErrors(bean, source, String operation, TransactionStatus transactionStatus) {

		if (!log.isWarnEnabled()) {
			return
		}

		def message = new StringBuilder()
		message << 'Problem in ' << source << ' at "' << operation <<
		message << '" ' << (isAttached(bean) ? 'updating' : 'creating') << ' '
		message << bean.getClass().simpleName << ': ' << bean

		def locale = LocaleContextHolder.getLocale()
		for (fieldErrors in bean.errors) {
			for (error in fieldErrors.allErrors) {
				message << '\n\t' << messageSource.getMessage(error, locale)
			}
		}

		log.warn message.toString()

		rollbackAndDiscard bean
	}

	void handleException(Throwable t, bean, Map properties, source, String operation,
			TransactionStatus transactionStatus) {

		boolean attached = bean && !(bean instanceof CommandObject) && bean.attached

		def message = new StringBuilder()
		message << 'Problem in ' << source << ' at "' << operation

		if (bean) {
			message << '" with bean ' << bean.getClass().simpleName << ': ' << bean
		}

		log.error message.toString(), t

		if (transactionStatus) {
			rollbackAndDiscard bean, transactionStatus
		}
	}

	protected boolean isAttached(bean) {
		bean && !(bean instanceof CommandObject) && bean.attached
	}

	protected void rollbackAndDiscard(bean, TransactionStatus transactionStatus) {

		if (bean && !(bean instanceof CommandObject)) {
			bean.discard()
		}

		transactionStatus.setRollbackOnly()
	}

	String encodePassword(String password, salt) {
		if (encodePassword) {
			password = springSecurityService.encodePassword(password, salt)
		}
		password
	}

	Closure<?> buildProjection(String path, String criterionMethod, List args) {

		log.debug "Building projection for path '$path': $criterionMethod($args)"

		def invoker = { String projectionName, Closure<?> subcriteria ->
			if (log.traceEnabled) {
				log.trace "Invoking projection $projectionName"
			}
			delegate."$projectionName"(subcriteria)
		}

		def closure = { ->
			if (log.traceEnabled) {
				log.trace "Invoking criterion $criterionMethod($args)"
			}
			delegate."$criterionMethod"(args)
		}

		for (String projectionName in (path.split('\\.').reverse())) {
			closure = invoker.clone().curry(projectionName, closure)
		}

		closure
	}

	def runCriteria(Class<?> clazz, List<Closure<?>> criterias, Map paginateParams) {
		clazz.createCriteria().list(paginateParams) {
			for (Closure<?> criteria in criterias) {
				criteria.delegate = delegate
				criteria()
			}
		}
	}

	protected void updatePassword(user, String password, TransactionStatus transactionStatus) {
		String salt = saltSource instanceof NullSaltSource ? null : uiPropertiesStrategy.getProperty(user, 'username')
		uiPropertiesStrategy.setProperties password: encodePassword(password, salt), user, transactionStatus
	}

	protected Class<?> unproxy(Class<?> clazz) {
		Class<?> current = clazz
		while (isProxy(current)) {
			current = current.superclass
		}
		current
	}

	protected boolean isProxy(Class<?> clazz) {
		if (clazz.superclass == Object) {
			return false
		}

		if (ClassUtils.isCglibProxyClass(clazz)) {
			return true
		}

		// Javassist
		clazz.interfaces.any { it.name.contains('org.hibernate.proxy.HibernateProxy') }
	}

	protected save(Map data, instanceOrClass, String methodName, transactionStatus, Closure callback = null) {

		assert transactionStatus

		def instance
		try {
			instance = uiPropertiesStrategy.setProperties(data, instanceOrClass, transactionStatus)

			if (callback) {
				callback instance
			}

			instance.save()
			if (instance.hasErrors()) {
				uiErrorsStrategy.handleValidationErrors instance, this, methodName, transactionStatus
			}
		}
		catch (e) {
			uiErrorsStrategy.handleException e, instance, data, this, methodName, transactionStatus
		}

		instance
	}

	/**
	 * When databinding and an object reference id isn't valid, the property will be a new
	 * 'transient' instance. If there are no validation errors, Hibernate will complain when
	 * flushing (typically with committing the transaction) 'an unsaved transient instance',
	 * so we remove the instance here before calling save(). If the property is nullable the
	 * update will succeed and the caller can handle the problem, and if it's not nullable
	 * this will trigger a validation error which is easier to handle than the exception
	 * that Hibernate throws.
	 *
	 * @param bean the bean (in practice only an AclEntry or AclObjectIdentity) since the
	 *             other domain classes don't have FK references
	 * @param propertyName the property name of the child object
	 */
	protected void removeIfTransient(bean, String... propertyNames) {
		def discardedNames = []
		for (propertyName in propertyNames) {
			def property = bean[propertyName]
			if (property && !property.attached) {
				bean[propertyName] = null
				discardedNames << propertyName
			}
		}

		if (discardedNames && log.warnEnabled) {
			log.warn 'Discarding transient properties ' + discardedNames + ' from ' + bean
		}
	}

	protected findUserByUsername(String username) {
		User.findWhere((classMappings[User].username): username)
	}

	protected boolean encodePassword
	protected String forgotPasswordEmailFrom
	protected String forgotPasswordEmailSubject
	protected List<String> registerDefaultRoleNames

	protected Class<?> AclClass
	protected Class<?> AclEntry
	protected Class<?> AclObjectIdentity
	protected Class<?> AclSid
	protected Class<?> Requestmap
	protected Class<?> Role
	protected Class<?> User
	protected Class<?> UserRole

	protected Map<String, Class<?>> domainClassesByControllerName = [:]

	void initialize() {
		def conf = SpringSecurityUtils.securityConfig

		def encode = conf.ui.encodePassword
		encodePassword = encode instanceof Boolean ? encode : false

		forgotPasswordEmailFrom = conf.ui.forgotPassword.emailFrom ?: ''
		forgotPasswordEmailSubject = conf.ui.forgotPassword.emailSubject ?: ''

		registerDefaultRoleNames = conf.ui.register.defaultRoleNames ?: []

		def getDomainClassClass = { String name ->
			if (name) return grailsApplication.getDomainClass(name)?.clazz
		}

		AclClass = getDomainClassClass(ACL_CLASS_NAME)
		AclEntry = getDomainClassClass(ACL_ENTRY_NAME)
		AclObjectIdentity = getDomainClassClass(ACL_OBJECT_IDENTITY_NAME)
		AclSid = getDomainClassClass(ACL_SID_NAME)
		Requestmap = getDomainClassClass(conf.requestMap.className)
		Role = getDomainClassClass(conf.authority.className)
		User = getDomainClassClass(conf.userLookup.userDomainClassName)
		UserRole = getDomainClassClass(conf.userLookup.authorityJoinClassName)

		domainClassesByControllerName = [requestmap: Requestmap, role: Role, user: User]

		classMappings = uiPropertiesStrategy.findClassMappings().asImmutable()
	}
}
