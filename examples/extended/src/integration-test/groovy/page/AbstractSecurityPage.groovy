package page

import geb.Page

abstract class AbstractSecurityPage extends Page {

	void submit() {
		submit.click()
	}

	protected boolean assertContentContains(String expected) {
		assert $().text().contains(expected) || $().text().contains(expected)
		true
	}

	protected boolean assertFuzzyContentContains(String expected, String expect2, String expect3) {
		assert $().text().contains(expected) || $().text().contains(expect2) || $().text().contains(expect3)
		true
	}

	protected boolean assertContentMatches(String regex) {
		assert $().text() ==~ regex
		true
	}

	protected boolean assertContentDoesNotContain(String unexpected) {
		assert !$().text().contains(unexpected)
		true
	}
}
