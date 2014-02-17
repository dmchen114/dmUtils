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
          'dm_common.c',
          'dm_list.c',
		  'dm_timer.c',
          'dm_socket.c'
        ],
      },
    ]
}