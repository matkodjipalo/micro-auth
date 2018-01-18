<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth;

use Micro\Auth\Adapter\AdapterInterface;
use Psr\Log\LoggerInterface as Logger;

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
