/* Copyright 2009-2016 the original author or authors.
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

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AclSidController extends AbstractS2UiDomainController {

	def create() {
		super.create()
	}

	def save() {
		withForm {
			doSave uiAclStrategy.saveAclSid(params)
		}.invalidToken {
			response.status = 500
			log.warn("User: ${SpringSecurityUtils.authentication.principal.id} possible CSRF or double submit: $params")
			flash.message = "${message(code: 'spring.security.ui.invalid.save.form', args: [params.username])}"
			redirect(action: "create")
			return
		}
	}

	def edit() {
		super.edit()
	}

	def update() {
		withForm {
			doUpdate { aclSid ->
				uiAclStrategy.updateAclSid params, aclSid
			}
		}.invalidToken {
			response.status = 500
			log.warn("User: ${SpringSecurityUtils.authentication.principal.id} possible CSRF or double submit: $params")
			flash.message = "${message(code: 'spring.security.ui.invalid.update.form', args: [params.username])}"
			redirectToSearch()
			return
		}
	}

	def delete() {
		withForm {
			tryDelete { aclSid ->
				uiAclStrategy.deleteAclSid aclSid
			}
		}.invalidToken {
			response.status = 500
			log.warn("User: ${SpringSecurityUtils.authentication.principal.id} possible CSRF or double submit: $params")
			flash.message = "${message(code: 'spring.security.ui.invalid.delete.form', args: [params.username])}"
			redirectToSearch()
		}
	}

	def search() {
		if (!isSearch()) {
			// show the form
			return
		}

		def results = doSearch { ->
			eqBoolean 'principal', delegate
			like 'sid', delegate
		}

		renderSearch([results: results, totalCount: results.totalCount],
		             'principal', 'sid')
	}

	protected Class<?> getClazz() { AclSid }
	protected String getClassLabelCode() { 'aclSid.label' }
	protected String getSimpleClassName() { 'AclSid' }
	protected Map model(aclSid, String action) {
		[aclSid: aclSid]
	}
}
