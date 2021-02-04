#define RN_ARG_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length;

#define RN_ARG_BUFFER(arg, len_check, error) \
  RN_ARG_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

#define RN_ARG_BUFFER_MIN_MAX(arg, min, max, error) \
  RN_ARG_BUFFER_NO_CHECK(arg) \
  if (arg##len < min || arg##len > max) return error;

#define RN_ARG_BUFFER_OR_NULL(arg) \
  NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned long arg##len = arg##_ns.length; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  if (arg##len == 0) arg##_data = NULL;

#define RN_ARG_BUFFER_MIN_MAX_OR_NULL(arg, min, max, error) \
  NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned long arg##len = arg##_ns.length; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  if (arg##len == 0) arg##_data = NULL; \
  else if (arg##len < min || arg##len > max) return error;

#define RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  const char *arg##_data = (const char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length; \

#define RN_ARG_CONST_BUFFER(arg, len_check, error) \
  RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

#define RN_ARG_CONST_BUFFER_MIN_MAX(arg, min, max, error) \
  RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  if (arg##len < min || arg##len > max) return error;

#define RN_RESULT_BUFFER_NO_CHECK(arg) \
  unsigned long long arg##len = [arg count]; \
  unsigned char *arg##_data = (unsigned char *) sodium_malloc([ arg count ]); \
  if (arg##_data == NULL) return ERR_FAILURE;

#define RN_RESULT_BUFFER(arg, length, error) \
  if ([arg count] != length) return error; \
  RN_RESULT_BUFFER_NO_CHECK(arg)

#define RN_RESULT_BUFFER_MIN_MAX(arg, min, max, error) \
  if ([arg count] < min || [arg count] > max) return error; \
  RN_RESULT_BUFFER_NO_CHECK(arg)

#define RN_ULL_MIN_MAX(arg, min, max, error) \
  unsigned long long arg##_val = [arg unsignedLongLongValue]; \
  if (arg##_val < min || arg##_val > max) return error;

#define RN_INT_MIN_MAX(arg, min, max, error) \
  int arg##_val = [arg intValue]; \
  if (arg##_val < min || arg##_val > max) return error;

#define RN_CHECK_FAILURE(call) \
  int result = call; \
  if (result != 0) return ERR_FAILURE;

#define RN_RETURN_BUFFER(arg) \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: arg##len]; \
  for (char i = 0; i < arg##len; i++) \
  { \
      [res addObject: [NSNumber numberWithUnsignedChar:arg##_data[i]]]; \
  } \
  return [res copy];
