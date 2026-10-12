/**
 * @name Juliet callable locations
 * @description Exports source ranges used to attach Juliet good/bad labels to SARIF alerts.
 * @kind table
 * @id fpm/juliet-callable-locations
 */

import java

from Callable callable, RefType declaringType, Location declaration, Location body
where
  callable.fromSource() and
  declaringType = callable.getDeclaringType() and
  declaration = callable.getLocation() and
  body = callable.getBody().getLocation()
select
  declaration.getFile().getRelativePath(),
  declaration.getStartLine(),
  body.getEndLine(),
  declaringType.getQualifiedName(),
  callable.getName()
