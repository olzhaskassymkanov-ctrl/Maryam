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
	'name': 'Username OSINT',
	'author': 'OSINT Team',
	'version': '1.0',
	'description': 'Search username across multiple public platforms and databases. Find digital footprint from legal open sources.',
	'sources': ('public_web'),
	'options': (
		('username', None, True, 'Username to search (without @ or domain)', '-u', 'store', str),
		('platforms', 'all', False, 'Platforms to search: all, social, code, academic (default=all)', '-p', 'store', str),
	),
	'examples': ('username_osint -u winxpsp1',
		'username_osint -u winxpsp1 -p social --output',
		'username_osint -u winxpsp1 -p code')
}

class UsernameOSINT:
	"""Search username across legal public platforms"""
	
	SOCIAL_PLATFORMS = {
		'twitter': {'url': 'https://twitter.com/{}', 'name': 'Twitter/X'},
		'reddit': {'url': 'https://reddit.com/user/{}', 'name': 'Reddit'},
		'instagram': {'url': 'https://instagram.com/{}', 'name': 'Instagram'},
		'youtube': {'url': 'https://youtube.com/@{}', 'name': 'YouTube'},
		'twitch': {'url': 'https://twitch.tv/{}', 'name': 'Twitch'},
		'tiktok': {'url': 'https://tiktok.com/@{}', 'name': 'TikTok'},
		'facebook': {'url': 'https://facebook.com/{}', 'name': 'Facebook'},
		'linkedin': {'url': 'https://linkedin.com/in/{}', 'name': 'LinkedIn'},
		'telegram': {'url': 'https://t.me/{}', 'name': 'Telegram'},
		'discord': {'url': 'https://discordapp.com/users/{}', 'name': 'Discord'},
	}
	
	CODE_PLATFORMS = {
		'github': {'url': 'https://github.com/{}', 'name': 'GitHub'},
		'gitlab': {'url': 'https://gitlab.com/{}', 'name': 'GitLab'},
		'bitbucket': {'url': 'https://bitbucket.org/{}', 'name': 'Bitbucket'},
		'codepen': {'url': 'https://codepen.io/{}', 'name': 'CodePen'},
		'stack_overflow': {'url': 'https://stackoverflow.com/users/{}', 'name': 'Stack Overflow'},
		'sourceforge': {'url': 'https://sourceforge.net/u/{}', 'name': 'SourceForge'},
	}
	
	ACADEMIC_PLATFORMS = {
		'google_scholar': {'url': 'https://scholar.google.com/scholar?q={}', 'name': 'Google Scholar'},
		'researchgate': {'url': 'https://researchgate.net/profile/{}', 'name': 'ResearchGate'},
		'academia': {'url': 'https://academia.edu/{}', 'name': 'Academia.edu'},
		'orcid': {'url': 'https://orcid.org/{}', 'name': 'ORCID'},
		'arxiv': {'url': 'https://arxiv.org/search/?query={}', 'name': 'arXiv'},
	}
	
	OTHER_PLATFORMS = {
		'medium': {'url': 'https://medium.com/@{}', 'name': 'Medium'},
		'dev_to': {'url': 'https://dev.to/{}', 'name': 'Dev.to'},
		'hashnode': {'url': 'https://hashnode.com/@{}', 'name': 'Hashnode'},
		'kaggle': {'url': 'https://kaggle.com/{}', 'name': 'Kaggle'},
		'patreon': {'url': 'https://patreon.com/{}', 'name': 'Patreon'},
		'gumroad': {'url': 'https://gumroad.com/{}', 'name': 'Gumroad'},
		'wordpress': {'url': 'https://{}.wordpress.com', 'name': 'WordPress'},
		'tumblr': {'url': 'https://{}.tumblr.com', 'name': 'Tumblr'},
	}
	
	def __init__(self, username):
		"""Initialize with username"""
		self.username = username.lstrip('@').strip().lower()
		self.results = {
			'username': self.username,
			'found_on': [],
			'not_found_on': [],
			'potential_profiles': []
		}
	
	def search_social(self):
		"""Generate social platform search URLs"""
		found = []
		not_found = []
		
		for key, platform in self.SOCIAL_PLATFORMS.items():
			url = platform['url'].format(self.username)
			found.append({
				'platform': platform['name'],
				'url': url,
				'type': 'social',
				'status': 'needs_verification'
			})
		
		return found
	
	def search_code(self):
		"""Generate code platform search URLs"""
		found = []
		
		for key, platform in self.CODE_PLATFORMS.items():
			url = platform['url'].format(self.username)
			found.append({
				'platform': platform['name'],
				'url': url,
				'type': 'code',
				'status': 'needs_verification'
			})
		
		return found
	
	def search_academic(self):
		"""Generate academic platform search URLs"""
		found = []
		
		for key, platform in self.ACADEMIC_PLATFORMS.items():
			url = platform['url'].format(self.username)
			found.append({
				'platform': platform['name'],
				'url': url,
				'type': 'academic',
				'status': 'needs_verification'
			})
		
		return found
	
	def search_other(self):
		"""Generate other platform search URLs"""
		found = []
		
		for key, platform in self.OTHER_PLATFORMS.items():
			url = platform['url'].format(self.username)
			found.append({
				'platform': platform['name'],
				'url': url,
				'type': 'other',
				'status': 'needs_verification'
			})
		
		return found
	
	def search_all_platforms(self):
		"""Search all platforms"""
		all_results = []
		all_results.extend(self.search_social())
		all_results.extend(self.search_code())
		all_results.extend(self.search_academic())
		all_results.extend(self.search_other())
		return all_results
	
	def get_search_recommendations(self):
		"""Get additional search recommendations"""
		recommendations = {
			'web_searches': [
				f'"{self.username}" -site:facebook.com',
				f'"{self.username}" telegram',
				f'"{self.username}" github',
				f'"{self.username}" twitter',
				f'{self.username} email',
			],
			'advanced_google_dorks': [
				f'intitle:{self.username}',
				f'inurl:{self.username}',
				f'site:github.com {self.username}',
				f'site:linkedin.com {self.username}',
				f'filetype:pdf {self.username}',
			],
			'username_variations': [
				self.username.replace('_', '.'),
				self.username.replace('_', '-'),
				self.username.replace('sp', 'SP'),
				self.username.replace('win', 'WIN'),
			],
			'tools': [
				'Sherlock - Username search tool',
				'OSRFramework - Open Source Research Framework',
				'Maltego - Graphical link analysis tool',
				'SpiderFoot - OSINT automation tool',
				'Metagoofil - Metadata extraction',
			]
		}
		return recommendations
	
	def full_analysis(self, platform_type='all'):
		"""Perform complete analysis"""
		if platform_type == 'social':
			platforms = self.search_social()
		elif platform_type == 'code':
			platforms = self.search_code()
		elif platform_type == 'academic':
			platforms = self.search_academic()
		else:
			platforms = self.search_all_platforms()
		
		return {
			'username': self.username,
			'search_type': platform_type,
			'total_platforms_checked': len(platforms),
			'platforms': platforms,
			'recommendations': self.get_search_recommendations(),
			'instructions': [
				'Visit each URL above to verify if the username exists',
				'Check for profile pictures, bios, and activity patterns',
				'Look for connected accounts and links',
				'Archive profile snapshots using Wayback Machine',
				'Cross-reference information across platforms',
				'Verify authenticity of found profiles'
			],
			'privacy_notice': [
				'This tool generates search URLs only',
				'All sources are publicly accessible',
				'Respect privacy and data protection laws',
				'Do not archive or download personal information',
				'Verify legal compliance before research'
			]
		}

def module_api(self):
	"""Module API function"""
	username = self.options['username']
	platforms = self.options['platforms'].lower()
	
	# Create analyzer
	analyzer = UsernameOSINT(username)
	
	# Perform analysis
	output = analyzer.full_analysis(platforms)
	
	# Save results
	self.save_gather(output, 'osint/username_search', username, output=self.options['output'])
	
	return output

def module_run(self):
	"""Module run function"""
	output = module_api(self)
	self.alert_results(output)
