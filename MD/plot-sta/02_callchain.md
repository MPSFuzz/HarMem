# 02 并排调用链 — 统计信息（代表性漏洞）

> 每个库选 1 个代表性漏洞，对比官方 harness 与生成 harness 的**库 API 调用序列**。

> 说明：这里列出的是 harness 源码层面直接调用的库 API（有序、去重、只统计函数调用）。
> 库内部完整调用链（如 png_read_info -> png_handle_IHDR -> ...）需库源码，另行分析。


## lua — LUA001（漏洞函数：`upvalname`）

- 生成 harness 是否**直接调用**漏洞函数：**否（经公开 API 间接到达）**
- 官方 harness 库 API 调用数：**52** | 生成 harness：**5**

官方 harness 调用序列：

`lua_sethook -> luaL_error -> lua_writestringerror -> lua_tostring -> lua_pop -> luaL_callmeta -> lua_type -> lua_pushfstring -> luaL_typename -> luaL_traceback -> lua_gettop -> lua_pushcfunction -> lua_insert -> lua_pcall -> lua_remove -> lua_writestring -> lua_writeline -> lua_createtable -> lua_pushstring -> lua_rawseti -> lua_setglobal -> luaL_loadfile -> luaL_loadbuffer -> lua_getglobal -> luaL_len -> luaL_checkstack -> lua_rawgeti -> lua_assert -> lua_warning -> lua_stdin_is_tty -> lua_initreadline -> lua_readline -> lua_saveline -> lua_freeline -> luaL_tolstring -> lua_tolstring -> lua_pushlstring -> lua_pushliteral -> lua_concat -> lua_settop -> lua_tointeger -> lua_touserdata -> luaL_checkversion -> lua_pushboolean -> lua_setfield -> luaL_openlibs -> lua_gc -> luaL_newstate -> lua_pushinteger -> lua_pushlightuserdata -> lua_toboolean -> lua_close`

生成 harness 调用序列：

`luaL_newstate -> luaL_openlibs -> luaL_loadbuffer -> lua_pcall -> lua_close`


## libpng — PNG002（漏洞函数：`png_image_free_function`）

- 生成 harness 是否**直接调用**漏洞函数：**否（经公开 API 间接到达）**
- 官方 harness 库 API 调用数：**25** | 生成 harness：**16**

官方 harness 调用序列：

`png_free -> png_destroy_read_struct -> png_get_io_ptr -> png_error -> png_sig_cmp -> png_create_info_struct -> png_set_mem_fn -> png_set_crc_action -> png_set_option -> png_set_read_fn -> png_set_sig_bytes -> png_jmpbuf -> png_read_info -> png_get_IHDR -> png_set_gray_to_rgb -> png_set_expand -> png_set_packing -> png_set_scale_16 -> png_set_tRNS_to_alpha -> png_set_interlace_handling -> png_read_update_info -> png_malloc -> png_get_rowbytes -> png_read_row -> png_read_end`

生成 harness 调用序列：

`png_create_read_struct -> png_create_info_struct -> png_destroy_read_struct -> png_jmpbuf -> png_set_progressive_read_fn -> png_process_data -> png_get_image_width -> png_get_image_height -> png_get_bit_depth -> png_get_color_type -> png_get_interlace_type -> png_get_compression_type -> png_get_filter_type -> png_read_update_info -> png_get_rowbytes -> png_read_row`


## libsndfile — SND005（漏洞函数：`aiff_read_chanmap`）

- 生成 harness 是否**直接调用**漏洞函数：**否（经公开 API 间接到达）**
- 官方 harness 库 API 调用数：**3** | 生成 harness：**2**

官方 harness 调用序列：

`sf_open_virtual -> sf_readf_float -> sf_close`

生成 harness 调用序列：

`sf_open -> sf_close`


## libtiff — TIF002（漏洞函数：`PixarLogDecode`）

- 生成 harness 是否**直接调用**漏洞函数：**否（经公开 API 间接到达）**
- 官方 harness 库 API 调用数：**7** | 生成 harness：**11**

官方 harness 调用序列：

`TIFFSetErrorHandler -> TIFFSetWarningHandler -> TIFFStreamOpen -> TIFFGetField -> TIFFTileSize64 -> TIFFClose -> TIFFReadRGBAImage`

生成 harness 调用序列：

`TIFFOpen -> TIFFGetField -> TIFFClose -> TIFFGetFieldDefaulted -> TIFFNumberOfTiles -> TIFFNumberOfStrips -> TIFFIsTiled -> TIFFTileSize -> TIFFStripSize -> TIFFReadEncodedTile -> TIFFReadEncodedStrip`


## libxml2 — XML001（漏洞函数：`xmlSnprintfElementContent`）

- 生成 harness 是否**直接调用**漏洞函数：**是**
- 官方 harness 库 API 调用数：**13** | 生成 harness：**13**

官方 harness 调用序列：

`xmlSetGenericErrorFunc -> xmlReadMemory -> xmlBufferCreate -> xmlSaveToBuffer -> xmlSaveDoc -> xmlSaveClose -> xmlFreeDoc -> xmlBufferFree -> xmlReaderForFile -> xmlTextReaderRead -> xmlTextReaderNodeType -> xmlTextReaderConstValue -> xmlFreeTextReader`

生成 harness 调用序列：

`xmlInitParser -> xmlSetGenericErrorFunc -> xmlReaderForMemory -> xmlTextReaderSetParserProp -> xmlTextReaderRead -> xmlTextReaderNodeType -> xmlTextReaderNextSibling -> xmlTextReaderCurrentDoc -> xmlGetIntSubset -> xmlHashScan -> xmlSnprintfElementContent -> xmlFreeTextReader -> xmlCleanupParser`


## sqlite3 — SQL002（漏洞函数：`selectExpander`）

- 生成 harness 是否**直接调用**漏洞函数：**否（经公开 API 间接到达）**
- 官方 harness 库 API 调用数：**15** | 生成 harness：**9**

官方 harness 调用序列：

`sqlite3_vfs_find -> sqlite3_strnicmp -> sqlite3_stricmp -> sqlite3_free -> sqlite3_mprintf -> sqlite3_initialize -> sqlite3_open_v2 -> sqlite3_progress_handler -> sqlite3_limit -> sqlite3_hard_heap_limit64 -> sqlite3_db_config -> sqlite3_set_authorizer -> sqlite3_complete -> sqlite3_exec -> sqlite3_close`

生成 harness 调用序列：

`sqlite3_exec -> sqlite3_free -> sqlite3_prepare_v2 -> sqlite3_step -> sqlite3_finalize -> sqlite3_initialize -> sqlite3_open -> sqlite3_close -> sqlite3_shutdown`

