# 02 Side-by-Side Call Chains — Statistics (Representative Vulnerabilities)

> For each library, one representative vulnerability is selected to compare the **library API call sequences** of the official harness and the generated harness.

> Note: what is listed here are the library APIs directly called at the harness source level (ordered, deduplicated, counting only function calls).
> The complete internal call chain of the library (e.g. png_read_info -> png_handle_IHDR -> ...) requires the library source and is analyzed separately.


## lua — LUA001 (vulnerability function: `upvalname`)

- Whether the generated harness **directly calls** the vulnerability function: **No (reached indirectly through public APIs)**
- Official harness library API call count: **52** | Generated harness: **5**

Official harness call sequence:

`lua_sethook -> luaL_error -> lua_writestringerror -> lua_tostring -> lua_pop -> luaL_callmeta -> lua_type -> lua_pushfstring -> luaL_typename -> luaL_traceback -> lua_gettop -> lua_pushcfunction -> lua_insert -> lua_pcall -> lua_remove -> lua_writestring -> lua_writeline -> lua_createtable -> lua_pushstring -> lua_rawseti -> lua_setglobal -> luaL_loadfile -> luaL_loadbuffer -> lua_getglobal -> luaL_len -> luaL_checkstack -> lua_rawgeti -> lua_assert -> lua_warning -> lua_stdin_is_tty -> lua_initreadline -> lua_readline -> lua_saveline -> lua_freeline -> luaL_tolstring -> lua_tolstring -> lua_pushlstring -> lua_pushliteral -> lua_concat -> lua_settop -> lua_tointeger -> lua_touserdata -> luaL_checkversion -> lua_pushboolean -> lua_setfield -> luaL_openlibs -> lua_gc -> luaL_newstate -> lua_pushinteger -> lua_pushlightuserdata -> lua_toboolean -> lua_close`

Generated harness call sequence:

`luaL_newstate -> luaL_openlibs -> luaL_loadbuffer -> lua_pcall -> lua_close`


## libpng — PNG002 (vulnerability function: `png_image_free_function`)

- Whether the generated harness **directly calls** the vulnerability function: **No (reached indirectly through public APIs)**
- Official harness library API call count: **25** | Generated harness: **16**

Official harness call sequence:

`png_free -> png_destroy_read_struct -> png_get_io_ptr -> png_error -> png_sig_cmp -> png_create_info_struct -> png_set_mem_fn -> png_set_crc_action -> png_set_option -> png_set_read_fn -> png_set_sig_bytes -> png_jmpbuf -> png_read_info -> png_get_IHDR -> png_set_gray_to_rgb -> png_set_expand -> png_set_packing -> png_set_scale_16 -> png_set_tRNS_to_alpha -> png_set_interlace_handling -> png_read_update_info -> png_malloc -> png_get_rowbytes -> png_read_row -> png_read_end`

Generated harness call sequence:

`png_create_read_struct -> png_create_info_struct -> png_destroy_read_struct -> png_jmpbuf -> png_set_progressive_read_fn -> png_process_data -> png_get_image_width -> png_get_image_height -> png_get_bit_depth -> png_get_color_type -> png_get_interlace_type -> png_get_compression_type -> png_get_filter_type -> png_read_update_info -> png_get_rowbytes -> png_read_row`


## libsndfile — SND005 (vulnerability function: `aiff_read_chanmap`)

- Whether the generated harness **directly calls** the vulnerability function: **No (reached indirectly through public APIs)**
- Official harness library API call count: **3** | Generated harness: **2**

Official harness call sequence:

`sf_open_virtual -> sf_readf_float -> sf_close`

Generated harness call sequence:

`sf_open -> sf_close`


## libtiff — TIF002 (vulnerability function: `PixarLogDecode`)

- Whether the generated harness **directly calls** the vulnerability function: **No (reached indirectly through public APIs)**
- Official harness library API call count: **7** | Generated harness: **11**

Official harness call sequence:

`TIFFSetErrorHandler -> TIFFSetWarningHandler -> TIFFStreamOpen -> TIFFGetField -> TIFFTileSize64 -> TIFFClose -> TIFFReadRGBAImage`

Generated harness call sequence:

`TIFFOpen -> TIFFGetField -> TIFFClose -> TIFFGetFieldDefaulted -> TIFFNumberOfTiles -> TIFFNumberOfStrips -> TIFFIsTiled -> TIFFTileSize -> TIFFStripSize -> TIFFReadEncodedTile -> TIFFReadEncodedStrip`


## libxml2 — XML001 (vulnerability function: `xmlSnprintfElementContent`)

- Whether the generated harness **directly calls** the vulnerability function: **Yes**
- Official harness library API call count: **13** | Generated harness: **13**

Official harness call sequence:

`xmlSetGenericErrorFunc -> xmlReadMemory -> xmlBufferCreate -> xmlSaveToBuffer -> xmlSaveDoc -> xmlSaveClose -> xmlFreeDoc -> xmlBufferFree -> xmlReaderForFile -> xmlTextReaderRead -> xmlTextReaderNodeType -> xmlTextReaderConstValue -> xmlFreeTextReader`

Generated harness call sequence:

`xmlInitParser -> xmlSetGenericErrorFunc -> xmlReaderForMemory -> xmlTextReaderSetParserProp -> xmlTextReaderRead -> xmlTextReaderNodeType -> xmlTextReaderNextSibling -> xmlTextReaderCurrentDoc -> xmlGetIntSubset -> xmlHashScan -> xmlSnprintfElementContent -> xmlFreeTextReader -> xmlCleanupParser`


## sqlite3 — SQL002 (vulnerability function: `selectExpander`)

- Whether the generated harness **directly calls** the vulnerability function: **No (reached indirectly through public APIs)**
- Official harness library API call count: **15** | Generated harness: **9**

Official harness call sequence:

`sqlite3_vfs_find -> sqlite3_strnicmp -> sqlite3_stricmp -> sqlite3_free -> sqlite3_mprintf -> sqlite3_initialize -> sqlite3_open_v2 -> sqlite3_progress_handler -> sqlite3_limit -> sqlite3_hard_heap_limit64 -> sqlite3_db_config -> sqlite3_set_authorizer -> sqlite3_complete -> sqlite3_exec -> sqlite3_close`

Generated harness call sequence:

`sqlite3_exec -> sqlite3_free -> sqlite3_prepare_v2 -> sqlite3_step -> sqlite3_finalize -> sqlite3_initialize -> sqlite3_open -> sqlite3_close -> sqlite3_shutdown`

