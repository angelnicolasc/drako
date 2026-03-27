// ruleid: SEC-005
const result = eval(userCode);
const fn = new Function('x', userExpression);
