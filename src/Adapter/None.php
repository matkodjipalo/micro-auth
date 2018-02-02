<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter;

class None extends AbstractAdapter
{
    /**
     * Authenticate.
     *
     * @return bool
     */
    public function authenticate(): bool
    {
        return true;
    }

    /**
     * Get identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return '';
    }

    /**
     * Get attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return [];
    }
}
