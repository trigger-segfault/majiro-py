$dic_add_word_con("\1");



//------------------------------------------------------
//======================================================

//'\q'で表示無しで待つマクロ
#subst "s/\\q/\\~\$pause_set_altwink();\$pause();\\~/"

/* flags */ "s"  // single line

/* match */ "\\q"

/* subst */ "\\~\$pause_set_altwink();\$pause();\\~"



//======================================================

//'※()'で辞書登録のマクロ
#subst "s/（(.*)）＊/\1\\f(12)※\\f(#confont_yl@SYSTEM)\$dic_add_word_con("\1");*/"
#subst "s/＊（(.*)）/\\f(12)※\\f(#confont_yl@SYSTEM)\$dic_add_word_con("\1");*\1/"


/* flags */ "s"  // single line

/* match */ "（(.*)）＊"

/* subst */ "\1\\f(12)※\\f(#confont_yl@SYSTEM)\$dic_add_word_con("\1");*"

/* input  */ "（Hello）＊"
/* output */ "Hello\f(12)※\f(#confont_yl@SYSTEM)$dic_add_word_con("Hello");*"