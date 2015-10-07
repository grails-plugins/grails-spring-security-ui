/* Copyright 2009-2013 SpringSource.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity.ui

import org.springframework.dao.DataIntegrityViolationException

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AclEntryController extends AbstractS2UiController {

	def aclPermissionFactory

	def create() {
		def aclEntry = lookupClass().newInstance(params)
		aclEntry.granting = true
		[aclEntry: aclEntry, sids: lookupAclSidClass().list()]
	}

	def save() {
		withForm {
			def aclEntry = lookupClass().newInstance(params)
			if (!aclEntry.save(flush: true)) {
				render view: 'create', model: [aclEntry: aclEntry, sids: lookupAclSidClass().list()]
				return
			}

			flash.message = "${message(code: 'default.created.message', args: [message(code: 'aclEntry.label', default: 'AclEntry'), aclEntry.id])}"
			redirect action: 'edit', id: aclEntry.id
		}.invalidToken {
			response.status = 500
			log.warn("User: ${springSecurityService.currentUser.id} possible CSRF or double submit: $params")
			flash.message = "${message(code: 'spring.security.ui.invalid.save.form', args: [params.className])}"
			redirect action: 'create'
			return
		}
	}

	def edit() {
		def aclEntry = findById()
		if (!aclEntry) return

		[aclEntry: aclEntry, sids: lookupAclSidClass().list()]
	}

	def update() {
		withForm {
			def aclEntry = findById()
			if (!aclEntry) return
			if (!versionCheck('aclEntry.label', 'AclEntry', aclEntry, [aclEntry: aclEntry])) {
				return
			}

			Long parentId = params.parent?.id ? params.parent.id.toLong() : null
			Long ownerId = params.owner?.id ? params.owner.id.toLong() : null
			if (!springSecurityUiService.updateAclEntry(aclEntry, params.aclObjectIdentity.id.toLong(),
					params.sid.id.toLong(), params.int('aceOrder'), params.int('mask'),
					params.granting == 'on', params.auditSuccess == 'on', params.auditFailure == 'on')) {
				render view: 'edit', model: [aclEntry: aclEntry, sids: lookupAclSidClass().list()]
				return
			}

			flash.message = "${message(code: 'default.updated.message', args: [message(code: 'aclEntry.label', default: 'AclEntry'), aclEntry.id])}"
			redirect action: 'edit', id: aclEntry.id
		}.invalidToken {
			response.status = 500
			log.warn("User: ${springSecurityService.currentUser.id} possible CSRF or double submit: $params")
			flash.message = "${message(code: 'spring.security.ui.invalid.update.form', args: [params.className])}"
			redirect action: 'search'
			return
		}
	}

	def delete() {
		def aclEntry = findById()
		if (!aclEntry) return

		try {
			withForm {
				springSecurityUiService.deleteAclEntry aclEntry
				flash.message = "${message(code: 'default.deleted.message', args: [message(code: 'aclEntry.label', default: 'AclEntry'), params.id])}"
				redirect action: 'search'
			}.invalidToken {
				response.status = 500
				log.warn("User: ${springSecurityService.currentUser.id} possible CSRF or double submit: $params")
				flash.message = "${message(code: 'spring.security.ui.invalid.delete.form', args: [params.className])}"
				redirect action: 'search'
				return
			}
		}
		catch (DataIntegrityViolationException e) {
			flash.error = "${message(code: 'default.not.deleted.message', args: [message(code: 'aclEntry.label', default: 'AclEntry'), params.id])}"
			redirect action: 'edit', id: params.id
		}
	}

	def search() {
		[granting: 0, auditSuccess: 0, auditFailure: 0, sids: lookupAclSidClass().list()]
	}

	def aclEntrySearch() {
		boolean useOffset = params.containsKey('offset')
		setIfMissing 'max', 10, 100
		setIfMissing 'offset', 0

		Integer max = params.int('max')
		Integer offset = params.int('offset')

		def cs = lookupClass().createCriteria()

		def results = cs.list(max: max, offset: offset) {
			firstResult: offset
			maxResults: max
			for (name in ['aceOrder', 'mask']) {
				if (params[name]) {
					eq(name,params.int(name))
				}
			}
			for (name in ['sid', 'aclObjectIdentity']) {
				if (params[name] && params[name] != 'null') {
					eq(name,params.long(name))
				}
			}
			for (name in ['granting', 'auditSuccess', 'auditFailure']) {
				Integer value = params.int(name)
				if (value) {
					eq(name,value == 1)
				}
			}

			if (params.aclClass) {
				/*
				 *  special case for external search - original query was
				 *  hql.append " AND e.aclObjectIdentity.aclClass.id=:aclClass"
				 *  
				 *  Looking up current version of the plugin ( 2.0-RC2)
				 *  AclEntry has a AclObjectIdentity aclObjectIdentity
				 *   AclObjectIdentity is created by extending AbstractAclObjectIdentity 
				 *   AbstractAclObjectIdentity contains AclClass aclClass 
				 *      
				 *   AbstractAclObjectIdentity is located in the grails-spring-security-acl at
				 *   /src/groovy/grails/plugin/springsecurity/acl/AbstractAclObjectIdentity.groovy
				 */
				
				aclObjectIdentity{
					aclClass{
						eq('id',params.long('aclClass'))
					}
				}
			}
			if (params.sort) {
				order(params.sort,params.order ?: 'ASC')
			}
		}

		def model = [results: results, totalCount: results.totalCount, searched: true,
			sids: lookupAclSidClass().list(), permissionFactory: aclPermissionFactory]
		// add query params to model for paging
		for (name in ['granting', 'auditSuccess', 'auditFailure', 'sid',
			'aclObjectIdentity', 'aceOrder', 'mask']) {
			model[name] = params[name]
		}

		render view: 'search', model: model
	}

	protected findById() {
		def aclEntry = lookupClass().get(params.id)
		if (!aclEntry) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'aclEntry.label', default: 'AclEntry'), params.id])}"
			redirect action: 'search'
		}

		aclEntry
	}

	protected String lookupClassName() {
		'grails.plugin.springsecurity.acl.AclEntry'
	}

	protected Class<?> lookupClass() {
		grailsApplication.getDomainClass(lookupClassName()).clazz
	}

	protected Class<?> lookupAclSidClass() {
		grailsApplication.getDomainClass('grails.plugin.springsecurity.acl.AclSid').clazz
	}
}
