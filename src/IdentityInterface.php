<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use Micro\Auth\Adapter\AdapterInterface;

interface IdentityInterface
{
    /**
     * Get attribute map.
     *
     * @return AttributeMap
     */
    public function getAttributeMap(): AttributeMapInterface;

    /**
     * Get adapter.
     *
     * @return AdapterInterface
     */
    public function getAdapter(): AdapterInterface;

    /**
     * Get identity.
     *
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * Get identity attributes.
     *
     * @return array
     */
    public function getAttributes(): array;
}
