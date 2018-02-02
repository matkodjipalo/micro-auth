<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use Closure;

interface AttributeMapInterface
{
    /**
     * Get attribute map.
     *
     * @return iterable
     */
    public function getAttributeMap(): Iterable;

    /**
     * Add custom mapper.
     *
     * @param string  $type
     * @param Closure $closure
     */
    public function addMapper(string $type, Closure $closure): self;

    /**
     * Prepare attributes.
     *
     * @param array $data
     *
     * @return array
     */
    public function map(array $data): array;
}
