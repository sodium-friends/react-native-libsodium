/*
  ARG BUFFER: arglen doesn't have to be mutatable
*/

#define RN_ARG_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length;

#define RN_ARG_BUFFER(arg, len_check, error) \
  RN_ARG_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

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

#define RN_ARG_UCONST_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  const unsigned char *arg##_data = (const unsigned char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length; \

#define RN_ARG_UCONST_BUFFER(arg, len_check, error) \
  RN_ARG_UCONST_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

#define RN_ARG_CONST_BUFFER_MIN_MAX(arg, min, max, error) \
  RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  if (arg##len < min || arg##len > max) return error;

/*
  RESULT BUFFER: arglen is written to by libsodium
*/

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

/*
  NUMBERS
*/

#define RN_ULL_MIN_MAX(arg, min, max, error) \
  unsigned long long arg##_val = [arg unsignedLongLongValue]; \
  if (arg##_val < min || arg##_val > max) return error;

#define RN_INT_MIN_MAX(arg, min, max, error) \
  int arg##_val = [arg intValue]; \
  if (arg##_val < min || arg##_val > max) return error;

/*
  FUNCTION CALLS
*/

#define RN_CHECK_FAILURE(call) \
  int result = call; \
  if (result != 0) return ERR_FAILURE;

/*
  RETURN DATA
*/

#define RN_RETURN_BUFFER(arg) \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: arg##len]; \
  RN_COPY_DATA(res, arg, arg##len) \
  return [res copy];

#define RN_RETURN_BUFFERS_2(buf1, buf2, b2len) \
  unsigned long long len = buf1##len + b2len; \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: len]; \
  RN_COPY_DATA(res, buf1, buf1##len) \
  RN_COPY_DATA(res, buf2, b2len) \
  return [res copy];

#define RN_RETURN_BUFFERS_3(buf1, buf2, buf3, b3len) \
  unsigned long long len = buf1##len + buf2##len + b3len; \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: len]; \
  RN_COPY_DATA(res, buf1, buf1##len) \
  RN_COPY_DATA(res, buf2, buf2##len) \
  RN_COPY_DATA(res, buf3, b3len) \
  return [res copy];

#define RN_COPY_DATA(res, buf, len) \
  for (int i = 0; i < len; i++) \
  { \
      [res addObject: [NSNumber numberWithUnsignedChar:buf##_data[i]]]; \
  }
