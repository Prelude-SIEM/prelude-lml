s/(0)//
s/classification/class/
s/assessment.//
s/(0)//
/^ source.node.address.category/i\
 source.node.address; \\
/^ target.node.address.category/i\
 target.node.address; \\
/^ id=/c\
 \\
/^ revision=/c\
 \\
s/(1)//
/^ source.user.userid.type/i\
 source.user.userid; \\
/^ target.user.userid.type/i\
 target.user.userid; \\
s/completion=success/completion=succeeded/
s/process=/process.name=/
