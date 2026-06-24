"""
OWASP Maryam!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

meta = {
	'name': 'Telegram User OSINT',
	'author': 'OSINT Team',
	'version': '1.0',
	'description': 'Search and analyze publicly available information about Telegram users from open sources.',
	'sources': ('google', 'bing', 'public_databases'),
	'options': (
		('username', None, True, 'Telegram username without @ (e.g. winxpsp1)', '-u', 'store', str),
		('search_engine', 'google', False, 'Search engine: google, bing, or both (default=google)', '-e', 'store', str),
	),
	'examples': ('telegram_osint -u winxpsp1',
		'telegram_osint -u winxpsp1 -e bing --output')
}

class TelegramOSINT:
	"""Analyze publicly available Telegram user information"""
	
	def __init__(self, username):
		"""Initialize with Telegram username"""
		self.username = username.lstrip('@').strip()
		self.results = {
			'username': self.username,
			'sources': []
		}
	
	def search_google(self):
		"""Search for username on Google"""
		google_results = {
			'engine': 'Google',
			'queries': [
				f'"{self.username}" telegram',
				f'@{self.username} telegram',
				f'{self.username} site:t.me',
				f'{self.username} telegram profile',
				f'{self.username} telegram user',
			],
			'public_sources': [
				'GitHub profiles',
				'Twitter/X mentions',
				'LinkedIn profiles',
				'Reddit discussions',
				'Forum posts',
				'News articles',
				'Academic databases',
				'Public repositories',
				'Portfolio websites',
				'Blog posts'
			]
		}
		return google_results
	
	def search_bing(self):
		"""Search for username on Bing"""
		bing_results = {
			'engine': 'Bing',
			'queries': [
				f'"{self.username}" telegram',
				f'{self.username} site:reddit.com',
				f'{self.username} site:twitter.com',
				f'{self.username} site:github.com',
				f'{self.username} site:linkedin.com',
			],
			'public_sources': [
				'Bing Image Search',
				'News Index',
				'Social Media Mentions',
				'Archived Content',
				'Public Records'
			]
		}
		return bing_results
	
	def analyze_username(self):
		"""Analyze username for patterns and clues"""
		analysis = {
			'username': self.username,
			'length': len(self.username),
			'character_types': {
				'lowercase': any(c.islower() for c in self.username),
				'uppercase': any(c.isupper() for c in self.username),
				'digits': any(c.isdigit() for c in self.username),
				'special_chars': any(not c.isalnum() for c in self.username)
			},
			'patterns': {
				'possible_reference': self._extract_patterns(),
				'common_suffix': self._check_common_suffix(),
				'numeric_ending': self._check_numeric_ending()
			}
		}
		return analysis
	
	def _extract_patterns(self):
		"""Extract potential patterns from username"""
		patterns = []
		
		# Check for common patterns
		if 'win' in self.username.lower():
			patterns.append('May reference Windows or gaming')
		if 'sp' in self.username.lower():
			patterns.append('Possible surname abbreviation')
		if self.username[0].isupper():
			patterns.append('Starts with capital letter - possibly real initials')
		
		return patterns
	
	def _check_common_suffix(self):
		"""Check for common suffixes"""
		common_suffixes = ['_', 'x', 'sp', 'bot', 'dev', 'admin']
		for suffix in common_suffixes:
			if self.username.endswith(suffix):
				return f"Ends with '{suffix}'"
		return None
	
	def _check_numeric_ending(self):
		"""Check for numeric patterns"""
		import re
		numeric_match = re.search(r'\d+$', self.username)
		if numeric_match:
			return f"Ends with number(s): {numeric_match.group()}"
		return None
	
	def get_public_databases(self):
		"""List of legal public databases to search"""
		databases = {
			'github': {
				'name': 'GitHub',
				'url': f'https://github.com/search?q={self.username}',
				'description': 'Source code repository and user profiles',
				'legal': True
			},
			'twitter': {
				'name': 'Twitter/X',
				'url': f'https://twitter.com/search?q={self.username}',
				'description': 'Social media mentions and profiles',
				'legal': True
			},
			'reddit': {
				'name': 'Reddit',
				'url': f'https://reddit.com/search?q={self.username}',
				'description': 'Forum discussions and user profiles',
				'legal': True
			},
			'linkedin': {
				'name': 'LinkedIn',
				'url': f'https://www.linkedin.com/search/results/people/?keywords={self.username}',
				'description': 'Professional profiles and connections',
				'legal': True
			},
			'google_scholar': {
				'name': 'Google Scholar',
				'url': f'https://scholar.google.com/scholar?q={self.username}',
				'description': 'Academic publications and research',
				'legal': True
			},
			'pastebin': {
				'name': 'Pastebin',
				'url': f'https://pastebin.com/search?q={self.username}',
				'description': 'Code snippets and text sharing',
				'legal': True
			},
			'stack_overflow': {
				'name': 'Stack Overflow',
				'url': f'https://stackoverflow.com/search?q={self.username}',
				'description': 'Programming Q&A platform',
				'legal': True
			},
			'youtube': {
				'name': 'YouTube',
				'url': f'https://www.youtube.com/results?search_query={self.username}',
				'description': 'Video platform and channels',
				'legal': True
			},
			'medium': {
				'name': 'Medium',
				'url': f'https://medium.com/search?q={self.username}',
				'description': 'Blogging platform',
				'legal': True
			},
			'kaggle': {
				'name': 'Kaggle',
				'url': f'https://www.kaggle.com/search?q={self.username}',
				'description': 'Data science and ML community',
				'legal': True
			}
		}
		return databases
	
	def full_analysis(self):
		"""Perform complete OSINT analysis"""
		return {
			'target': self.username,
			'disclaimer': 'This analysis uses only publicly available and legal sources',
			'username_analysis': self.analyze_username(),
			'search_strategies': {
				'google': self.search_google(),
				'bing': self.search_bing()
			},
			'public_databases': self.get_public_databases(),
			'recommended_actions': [
				'1. Search on GitHub to find code repositories and projects',
				'2. Check Twitter/X for mentions and public discussions',
				'3. Look on Reddit for community participation',
				'4. Search LinkedIn for professional information',
				'5. Check Google Scholar for academic work',
				'6. Monitor Stack Overflow for technical Q&A',
				'7. Search YouTube for video content',
				'8. Check Medium for blog posts',
				'9. Look for news mentions via news search',
				'10. Combine findings to build comprehensive profile'
			],
			'ethical_guidelines': [
				'Only use publicly available information',
				'Respect privacy and local laws',
				'Do not attempt unauthorized access',
				'Do not share personal information without consent',
				'Verify information from multiple sources',
				'Consider the purpose and legality of your research'
			]
		}

def module_api(self):
	"""Module API function"""
	username = self.options['username']
	search_engine = self.options['search_engine'].lower()
	
	# Create analyzer
	analyzer = TelegramOSINT(username)
	
	# Perform analysis
	output = analyzer.full_analysis()
	
	# Save results
	self.save_gather(output, 'osint/telegram_osint', username, output=self.options['output'])
	
	return output

def module_run(self):
	"""Module run function"""
	output = module_api(self)
	self.alert_results(output)
