/* Copyright 2015-2016 the original author or authors.
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


class ForgotPasswordCommand implements CommandObject, grails.validation.Validateable  {
    String username
    /* TODO: Add it so it supports multplie paramaters..default will be just one..This is fine for just entering some token but not great for anything else
     * ie Challenge questions.
     */
    String extraValidationString
    def extraValidation = [do:'',prop:'']

    public void setExtraValidation(String domainObject,String DoProperty){
        this.extraValidation.do = domainObject
        this.extraValidation.prop = DoProperty
    }

    static constraints = {
        extraValidationString nullable: true
    }
}