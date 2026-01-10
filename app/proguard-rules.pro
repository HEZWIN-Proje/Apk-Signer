# Keep apksig library classes
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# Keep keystore related classes
-keep class java.security.** { *; }
-keep class javax.crypto.** { *; }

# Keep application classes
-keep class com.hezwin.apksigner.** { *; }

# Preserve line numbers for debugging stack traces
-keepattributes SourceFile,LineNumberTable

# Hide the original source file name
-renamesourcefileattribute SourceFile

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}