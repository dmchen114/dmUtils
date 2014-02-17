{
    'variables': {
    },
    'includes': [
      '../common.gypi',
    ],
    'target_defaults': {
    },
	'targets': [
      {
        'target_name': 'dmUtils',
        'type': '<(library)',
		'include_dirs': [
            '../include',
        ],        
		'sources': [
          '../src/dm_common.c',
          '../src/dm_list.c',
		  '../src/dm_timer.c',
          '../src/dm_socket.c'
        ],
        'conditions': [
            [ 'OS=="win"', {
                    'defines': [
                        '_GNU_SOURCE', 'WIN32', 'SERVER', 'ENABLE_DMLOG', '_CONSOLE'
                    ],
                }, {
                    'defines': [
                        '_GNU_SOURCE', 'LINUX', 'SERVER', 'ENABLE_DMLOG', '_LINUX'
                    ],
                }
            ]
        ]
      },
      {
        'target_name': 'test',
        'type': 'executable',
		'include_dirs': [
            '../include',
        ],        
		'sources': [
          '../test/timer_test.c',
          '../test/main.c'
        ],
        'dependencies': [
          'dmUtils'
        ],
        'conditions': [
            [ 'OS=="win"', {
                    'defines': [
                        '_GNU_SOURCE', 'WIN32', 'SERVER', 'ENABLE_DMLOG', '_CONSOLE'
                    ],
                    'link_settings': {
                        'libraries': [
                            '-lws2_32.lib', '-lkernel32.lib', '-luser32.lib', '-lgdi32.lib'
                        ]
                    }
                }, {
                    'defines': [
                        '_GNU_SOURCE', 'LINUX', 'SERVER', 'ENABLE_DMLOG', '_LINUX'
                    ],
                    'link_settings': {
                        'libraries': [
                            '-lpthread', '-lm', '-ldl', '-lrt'
                        ]
                    }
                }
            ]
        ]
      }
    ]
}