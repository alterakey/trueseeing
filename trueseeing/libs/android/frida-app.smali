.class public final {{cn}}
.super {{base}}
.source "SourceFile"

# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, {{base}}-><init>()V

    const-string v0, "{{lib}}"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
